const { MongoClient } = require('mongodb');
const jwt = require('jsonwebtoken');

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
  // 只允许GET请求
  if (event.httpMethod !== 'GET') {
    return {
      statusCode: 405,
      body: JSON.stringify({ error: 'Method not allowed' }),
    };
  }

  try {
    // 从Authorization头获取token
    const authHeader = event.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return {
        statusCode: 401,
        body: JSON.stringify({ error: '未提供访问令牌' }),
      };
    }
    
    const token = authHeader.substring(7); // 去掉"Bearer "前缀
    
    // 验证token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      return {
        statusCode: 401,
        body: JSON.stringify({ error: '无效的访问令牌' }),
      };
    }
    
    // 连接数据库
    const db = await connectToDatabase();
    const usersCollection = db.collection('users');
    
    // 查找用户
    const user = await usersCollection.findOne({ _id: decoded.userId });
    if (!user) {
      return {
        statusCode: 404,
        body: JSON.stringify({ error: '用户不存在' }),
      };
    }
    
    // 返回用户信息（不包含密码）
    const { password, ...userWithoutPassword } = user;
    
    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Allow-Methods': 'GET, OPTIONS'
      },
      body: JSON.stringify({
        valid: true,
        user: userWithoutPassword
      }),
    };
  } catch (error) {
    console.error('令牌验证错误:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: '服务器内部错误' }),
    };
  }
};
