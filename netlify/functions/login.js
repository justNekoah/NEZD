const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// 模拟数据库 - 实际应用中应使用真实数据库
let users = [];

exports.handler = async (event, context) => {
  try {
    const { username, password } = JSON.parse(event.body);

    // 验证输入
    if (!username || !password) {
      return {
        statusCode: 400,
        body: JSON.stringify({ 
          success: false, 
          message: '请提供用户名和密码' 
        })
      };
    }

    // 查找用户（支持用户名或邮箱登录）
    const user = users.find(u => u.username === username || u.email === username);
    if (!user) {
      return {
        statusCode: 400,
        body: JSON.stringify({ 
          success: false, 
          message: '用户名或密码错误' 
        })
      };
    }

    // 验证密码
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return {
        statusCode: 400,
        body: JSON.stringify({ 
          success: false, 
          message: '用户名或密码错误' 
        })
      };
    }

    // 生成JWT令牌
    const token = jwt.sign(
      { userId: user.id }, 
      process.env.JWT_SECRET, 
      { expiresIn: '24h' }
    );

    // 返回成功响应（不返回密码）
    const { password: _, ...userWithoutPassword } = user;
    return {
      statusCode: 200,
      body: JSON.stringify({
        success: true,
        message: '登录成功',
        user: userWithoutPassword,
        token
      })
    };

  } catch (error) {
    console.error('登录错误:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ 
        success: false, 
        message: '服务器内部错误' 
      })
    };
  }
};
