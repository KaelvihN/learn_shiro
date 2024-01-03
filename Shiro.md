# Shiro #

## 简介

**Shiro**是由Apache维护的一个强大，易用，轻量级的安全框架。他提供了**认证，授权，加密等功能**。**Shiro**与**Spring Security**相比，**Shiro**也许没有**Spring Security**那么强大。但是**Shiro**更灵活和更轻量，**Shiro**可以不依赖**Spring**,甚至可以在非**Web环境**下使用，这是**Spring Security**所不能实现的。

> Shiro基本功能 

**Shiro**可以非常容易的开发出足够好的应用，其不仅可以用在**Web环境**，也可以用在 **JavaEE环境**。**Shiro**可以帮助我们完成：**认证、授权、加密、会话管理、与 Web 集成、缓存等**。其基本功能点如下图所示：

![Shiro基本功能](https://image.kaelvihn.top/article/2024-01-03-1.png)

- `Authentication`：**身份认证/登录**，验证用户是不是拥有相应的身份

- `Authorization`：**授权，即验证权限**，验证用户是否有权限去访问某些资源
- `Session Management`：**会话管理**。用户登录后就是一次会话，在用户没有退出登录前，它的所有信息都存在会话中
- `Cryptography`：**加密**，保护数据安全，我们可以使用`(Password+Salt)MD5*frequency`即密码＋盐拼接后，在进行多次MD5加密
- `Web Support`：**Web支持**，可以非常容易的集成到 Web 环境
- `Caching`：**缓存**，比如用户登录后，其用户信息、拥有的角色/权限不必每次去查，这样可以提高效率
- `Concurrency`：**shiro支持多线程应用的并发验证**，即如在一个线程中开启另一个线程，能把权限自动传播过去
- `Testing`：**提供测试支持**
- `Run As`：允许一个用户假装为另一个用户（如果他们允许）的身份进行访问
- `Remember Me`：**记住我、避免重复登录**，这个是非常常见的功能，即一次登录后，下次再来的话不用登录了

> Shiro架构

![](https://image.kaelvihn.top/article/2024-01-03-2.png)