const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

// 模拟数据库 - 实际应用中应使用真实数据库
let users = [];

exports.handler = async (event, context) => {
  try {
    const { username, email, password } = JSON.parse(event.body);

    // 验证输入
    if (!username || !email || !password) {
      return {
        statusCode: 400,
        body: JSON.stringify({ 
          success: false, 
          message: '请提供用户名、邮箱和密码' 
        })
      };
    }

    // 检查用户是否已存在
    if (users.find(u => u.username === username)) {
      return {
        statusCode: 400,
        body: JSON.stringify({ 
          success: false, 
          message: '用户名已存在' 
        })
      };
    }

    if (users.find(u => u.email === email)) {
      return {
        statusCode: 400,
        body: JSON.stringify({ 
          success: false, 
          message: '邮箱已被注册' 
        })
      };
    }

    // 密码强度验证
    if (password.length < 6) {
      return {
        statusCode: 400,
        body: JSON.stringify({ 
          success: false, 
          message: '密码长度至少为6位' 
        })
      };
    }

    // 哈希密码
    const hashedPassword = await bcrypt.hash(password, 10);

    // 创建用户
    const user = {
      id: uuidv4(),
      username,
      email,
      password: hashedPassword,
      createdAt: new Date().toISOString()
    };

    users.push(user);

    // 生成JWT令牌
    const jwt = require('jsonwebtoken');
    const token = jwt.sign(
      { userId: user.id }, 
      process.env.JWT_SECRET, 
      { expiresIn: '24h' }
    );

    // 返回成功响应（不返回密码）
    const { password: _, ...userWithoutPassword } = user;
    return {
      statusCode: 201,
      body: JSON.stringify({
        success: true,
        message: '用户注册成功',
        user: userWithoutPassword,
        token
      })
    };

  } catch (error) {
    console.error('注册错误:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ 
        success: false, 
        message: '服务器内部错误' 
      })
    };
  }
};
