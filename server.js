require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const winston = require('winston');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const helmet = require('helmet');
const uuid = require('uuid');
const NodeCache = require('node-cache');

const app = express();

// 安全头设置
app.use(helmet());
app.use(express.json());
app.use(cors({
    origin: ['http://localhost:5500', 'https://your-domain.vercel.app'],
    credentials: true,
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// 日志配置
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
        new winston.transports.File({ filename: 'logs/combined.log' }),
        new winston.transports.Console({
            format: winston.format.simple()
        })
    ]
});

// 会话管理
app.use(session({
    store: new FileStore({
        path: './sessions',
        ttl: 86400, // 24小时过期
        reapInterval: 3600 // 每小时清理过期会话
    }),
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: false,
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24小时
    }
}));

// 环境变量
const API_KEY = process.env.ZHIPU_API_KEY;
const PORT = process.env.PORT || 3000;

// IP黑名单
const blacklistedIPs = new Set();

// IP封禁中间件
const checkIPBan = (req, res, next) => {
    const clientIP = req.ip;
    if (blacklistedIPs.has(clientIP)) {
        logger.warn(`Blocked request from banned IP: ${clientIP}`);
        return res.status(403).json({ error: 'IP已被封禁' });
    }
    next();
};

// 速率限制
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: '请求过于频繁，请稍后再试',
    handler: (req, res) => {
        logger.warn(`Rate limit exceeded for IP: ${req.ip}`);
        // 连续超限5次则封禁IP
        const violations = req.rateLimit.current;
        if (violations >= 5) {
            blacklistedIPs.add(req.ip);
            logger.warn(`IP banned due to multiple violations: ${req.ip}`);
        }
        res.status(429).json({ error: '请求过于频繁，请稍后再试' });
    }
});

app.use(checkIPBan);
app.use('/api/chat', limiter);

// 对话上下文管理
const conversationContexts = new Map();
const MAX_CONTEXT_LENGTH = 4; // 限制上下文长度
const CONTEXT_EXPIRE_TIME = 30 * 60 * 1000; // 30分钟过期

function getConversationContext(sessionId) {
    if (!conversationContexts.has(sessionId)) {
        conversationContexts.set(sessionId, {
            messages: [],
            lastAccess: Date.now()
        });
    }
    const context = conversationContexts.get(sessionId);
    context.lastAccess = Date.now();
    return context.messages;
}

// 定期清理过期的上下文
setInterval(() => {
    const now = Date.now();
    for (const [sessionId, context] of conversationContexts.entries()) {
        if (now - context.lastAccess > CONTEXT_EXPIRE_TIME) {
            conversationContexts.delete(sessionId);
        }
    }
}, 5 * 60 * 1000); // 每5分钟检查一次

// Token管理
let cachedToken = null;
let tokenExpiration = 0;

function generateToken() {
    try {
        const [id, secret] = API_KEY.split('.');
        const now = Date.now();
        
        const header = {
            alg: 'HS256',
            sign_type: 'SIGN'
        };
        
        const payload = {
            api_key: id,
            exp: now + 3600000,
            timestamp: now
        };
        
        const token = jwt.sign(payload, secret, { 
            algorithm: 'HS256',
            header: header 
        });
        
        return { token, expiration: now + 3600000 };
    } catch (error) {
        console.error('Token generation failed:', error);
        throw new Error('Invalid API Key');
    }
}

function getValidToken() {
    const now = Date.now();
    if (cachedToken && tokenExpiration - now > 1800000) {
        return cachedToken;
    }
    
    const { token, expiration } = generateToken();
    cachedToken = token;
    tokenExpiration = expiration;
    return token;
}

// 重试机制
async function makeRequestWithRetry(message, context, maxRetries = 3) {
    let lastError;
    for (let i = 0; i < maxRetries; i++) {
        try {
            // 只保留最近的几轮对话
            const recentContext = context.slice(-MAX_CONTEXT_LENGTH * 2);
            const messages = [...recentContext, { role: 'user', content: message }];

            const response = await axios.post('https://open.bigmodel.cn/api/paas/v4/chat/completions', {
                model: 'glm-4',
                messages: messages,
                temperature: 0.7,
                top_p: 0.95,
                max_tokens: 300,  // 减少token数量以加快响应
                presence_penalty: 0.6,
                frequency_penalty: 0.3,
                stream: true
            }, {
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${getValidToken()}`
                },
                timeout: 5000,  // 减少超时时间
                responseType: 'stream'
            });
            
            // 添加请求计数和限制
            if (!global.requestCount) {
                global.requestCount = 0;
            }
            global.requestCount++;

            // 如果请求过于频繁，增加延迟
            if (global.requestCount > 10) {
                await new Promise(resolve => setTimeout(resolve, 1000));
                global.requestCount = 0;
            }

            return response;
        } catch (error) {
            lastError = error;
            if (error.code === 'ECONNABORTED') {
                continue;
            }
            logger.error('API request failed:', { 
                error: error.message, 
                attempt: i + 1,
                response: error.response?.data
            });
            if (i === maxRetries - 1) break;
            await new Promise(resolve => setTimeout(resolve, 500));
        }
    }
    throw new Error(`API调用失败 (${maxRetries}次尝试): ${lastError.message}`);
}

// 初始化缓存
const responseCache = new NodeCache({
    stdTTL: 3600, // 1小时过期
    checkperiod: 600, // 每10分钟检查过期
    maxKeys: 1000 // 最多缓存1000条
});

// 预热问题列表
const WARM_UP_QUESTIONS = [
    "你好",
    "你是谁",
    "你能做什么",
    "介绍一下你自己"
];

// 预热缓存
async function warmUpCache() {
    try {
        logger.info('Starting cache warm-up...');
        for (const question of WARM_UP_QUESTIONS) {
            if (!responseCache.has(question)) {
                const response = await makeRequestWithRetry(question, [], 1);
                let fullResponse = '';
                
                await new Promise((resolve, reject) => {
                    response.data.on('data', chunk => {
                        try {
                            const lines = chunk.toString().split('\n');
                            for (const line of lines) {
                                if (line.startsWith('data: ')) {
                                    const data = JSON.parse(line.slice(6));
                                    if (data.choices && data.choices[0].delta.content) {
                                        fullResponse += data.choices[0].delta.content;
                                    }
                                }
                            }
                        } catch (error) {
                            reject(error);
                        }
                    });
                    
                    response.data.on('end', () => {
                        responseCache.set(question, fullResponse);
                        resolve();
                    });
                    
                    response.data.on('error', reject);
                });
            }
        }
        logger.info('Cache warm-up completed');
    } catch (error) {
        logger.error('Cache warm-up failed:', error);
    }
}

// 启动时预热缓存
warmUpCache();

// 每6小时重新预热一次
setInterval(warmUpCache, 6 * 60 * 60 * 1000);

// API端点
app.post('/api/chat', async (req, res) => {
    try {
        // 添加请求节流
        if (global.requestCount > 20) {
            throw new Error('服务器繁忙，请稍后再试');
        }

        if (!req.session.id) {
            req.session.id = uuid.v4();
        }

        if (!req.body.message || typeof req.body.message !== 'string') {
            throw new Error('无效的消息格式');
        }

        const { message } = req.body;

        // 检查缓存
        const cachedResponse = responseCache.get(message);
        if (cachedResponse) {
            logger.info('Cache hit:', { message });
            res.write(`data: ${JSON.stringify({ content: cachedResponse })}\n\n`);
            res.write('data: [DONE]\n\n');
            res.end();
            return;
        }

        const context = getConversationContext(req.session.id);

        logger.info('Chat request received', {
            sessionId: req.session.id,
            message: message,
            ip: req.ip
        });

        // 设置SSE头
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');

        const response = await makeRequestWithRetry(message, context);
        
        let fullResponse = '';
        response.data.on('data', chunk => {
            try {
                const lines = chunk.toString().split('\n');
                for (const line of lines) {
                    if (line.startsWith('data: ')) {
                        const data = JSON.parse(line.slice(6));
                        if (data.choices && data.choices[0].delta.content) {
                            const content = data.choices[0].delta.content;
                            fullResponse += content;
                            res.write(`data: ${JSON.stringify({ content })}\n\n`);
                        }
                    }
                }
            } catch (error) {
                logger.error('Error processing stream chunk:', error);
            }
        });

        response.data.on('end', () => {
            context.push({ role: 'user', content: message });
            context.push({ role: 'assistant', content: fullResponse });
            
            // 保持上下文在限制范围内
            while (context.length > MAX_CONTEXT_LENGTH * 2) {
                context.splice(0, 2);
            }
            
            // 缓存响应
            if (message.length < 100 && fullResponse.length < 500) {
                responseCache.set(message, fullResponse);
            }

            res.write('data: [DONE]\n\n');
            res.end();
            
            logger.info('Chat response completed', {
                sessionId: req.session.id,
                responseLength: fullResponse.length
            });
        });

    } catch (error) {
        const errorMessage = error.response?.data?.error || error.message;
        logger.error('Chat API Error', {
            error: errorMessage,
            stack: error.stack,
            sessionId: req.session?.id,
            statusCode: error.response?.status
        });

        res.write(`data: ${JSON.stringify({
            error: '服务器错误',
            message: `请求处理失败: ${errorMessage}`
        })}\n\n`);
        res.end();
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
    logger.info(`Server started on port ${PORT}`);
}); 