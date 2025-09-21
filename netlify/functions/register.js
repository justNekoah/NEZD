const { MongoClient } = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

let cachedDb = null;

async function connectToDatabase() {
  if (cachedDb) {
    return cachedDb;
  }
  
  const client = await MongoClient.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });
  
  const db = client.db();
  cachedDb = db;
  return db;
}

exports.handler = async (event, context) => {
  // 只允许POST请求
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      body: JSON.stringify({ error: 'Method not allowed' }),
    };
  }

  try {
    const { username, email, password } = JSON.parse(event.body);
    
    // 验证输入
    if (!username || !email || !password) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: '用户名、邮箱和密码不能为空' }),
      };
    }
    
    if (username.length < 5) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: '用户名至少需要5个字符' }),
      };
    }
    
    if (password.length < 6) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: '密码至少需要6位' }),
      };
    }
    
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: '请输入有效的电子邮箱' }),
      };
    }

    // 连接数据库
    const db = await connectToDatabase();
    const usersCollection = db.collection('users');
    
    // 检查用户是否已存在
    const existingUser = await usersCollection.findOne({
      $or: [
        { username: username },
        { email: email }
      ]
    });
    
    if (existingUser) {
      return {
        statusCode: 409,
        body: JSON.stringify({ error: '用户名或邮箱已被注册' }),
      };
    }
    
    // 哈希密码
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    
    // 创建用户
    const user = {
      _id: uuidv4(),
      username,
      email,
      password: hashedPassword,
      createdAt: new Date(),
      updatedAt: new Date(),
      lastLogin: null
    };
    
    // 保存用户到数据库
    await usersCollection.insertOne(user);
    
    // 生成JWT令牌
    const token = jwt.sign(
      { 
        userId: user._id,
        username: user.username,
        email: user.email 
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    // 返回成功响应（不包含密码）
    const { password: _, ...userWithoutPassword } = user;
    
    return {
      statusCode: 201,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST, OPTIONS'
      },
      body: JSON.stringify({
        message: '注册成功',
        token,
        user: userWithoutPassword
      }),
    };
  } catch (error) {
    console.error('注册错误:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: '服务器内部错误' }),
    };
  }
};
