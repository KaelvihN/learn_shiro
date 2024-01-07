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

![应用程序角度的工作流程图](https://image.kaelvihn.top/article/2024-01-03-2.png)

- `Subject`：**主体**，代表了当前用户(不一定是人，有可能是爬虫或者是机器人)
- `SecurityManger`：**安全管理器**,所有的与安全相关的操作抖会与其交互，并且他管理所有的**Subject**，是Shiro的核心
- `Realm`：**域**，Shiro从Realm获取安全数据(用户，角色，权限)，数据源可以是JDBC实现，也可以是LDAP实现，或者内存实现等等。获取到的数据需要交给**SecurityManger**进行验证

![内部程序角度的Shiro架构](https://image.kaelvihn.top/article/2024-01-03-3.png)

- `Authenticator`：**认证器**，负责主体认证的，这是一个扩展点，可以自定义实现；其需要认证策略（Authentication Strategy），即什么情况下算用户认证通过了
- `Authorizer`：**授权器**，或者访问控制器，用来决定主体是否有权限进行相应的操作；即控制着用户能访问应用中的哪些功能
- `SessionDAO`：**数据访问对象**，用于会话的 CRUD，比如我们想把 Session 保存到数据库，那么可以实现自己的 SessionDAO，通过如 JDBC 写到数据库；比如想把 Session 放到 Memcached 中，可以实现自己的 Memcached SessionDAO；另外 SessionDAO 中可以使用 Cache 进行缓存，以提高性能；
- `CacheManager`：**缓存控制器**，来管理如用户、角色、权限等的缓存的；因为这些数据基本上很少去改变，放到缓存中后可以提高访问的性能
- `Cryptography`：**密码模块**，Shiro 提供了一些常见的加密组件用于如密码加密 /解密的。

## Shiro的身份验证

### 身份验证 ###

**身份验证**，即在应用中验证他就是他本人。一般提供(**UserId**，**UserName**，**telephone**，**email**等)+(**password**,**验证码**等)标识信息来表明他就是他本人。在Shiro中，用户提供`principals`(身份)和`credentials`(证明)给Shiro，从而应用能验证用户身份。

- `Principals`：身份，即主体的标识属性，可以使任何东西。如用户名，邮箱...唯一即可。一个主体可以有多个`principals`，但是只有一个`primary principals`,一般是用户名，密码，手机号。
- `credentials`：证明/凭证，即只有主体知道的安全值，如密码/数字证...

最常见的 `principals` 和 `credentials` 组合就是用户名 / 密码了。接下来先进行一个基本的身份认证。

![工作流程图](https://image.kaelvihn.top/article/2024-01-04-1.png)

> 简单实现

**引入依赖：**

```xml
<dependencies>
        <dependency>
            <groupId>commons-logging</groupId>
            <artifactId>commons-logging</artifactId>
            <version>1.1.3</version>
        </dependency>
        <dependency>
            <groupId>org.apache.shiro</groupId>
            <artifactId>shiro-core</artifactId>
            <version>1.12.0</version>
        </dependency>
        <dependency>
            <groupId>log4j</groupId>
            <artifactId>log4j</artifactId>
            <version>1.2.17</version>
        </dependency>
</dependencies>
```

**准备凭据：**

```ini
[users]
tuids=123
araneidasword=123
```

**代码实现**：

```java
/**
 * @author tuids
 * @date 2024/1/4 0:30
 */
public class ShiroApp {
    static Logger logger;

    static {
        BasicConfigurator.configure();
        logger = Logger.getLogger(ShiroApp.class);

    }

    public static void main(String[] args) {
        // 创建SecurityManger工厂，此处使用Ini文件充当数据源来初始化SecurityManger
        IniSecurityManagerFactory securityManagerFactory
                = new IniSecurityManagerFactory("classpath:shiro.ini");
        //创建对象实例，并绑定给SecurityUtils
        SecurityManager securityManager = securityManagerFactory.createInstance();
        SecurityUtils.setSecurityManager(securityManager);
        //得到Subject，创建username/password 验证 token
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("tuids", "1235");
        try {
            //登录验证身份
            subject.login(token);
            logger.info("登录成功," + subject.isAuthenticated());
        } catch (AuthenticationException e) {
            //登录失败
            logger.error("登录失败,失败原因:" + e);
        }
        //6、退出
        subject.logout();
    }
}
```

### Raelm 

`Realm`：**域**，Shiro从Realm获取安全数据(用户，角色，权限)，数据源可以是JDBC实现，也可以是LDAP实现，或者内存实现等等。获取到的数据需要交给**SecurityManger**进行验证。上面的例子使用的就是Realm的一个实现类`IniRealm`。正常情况下我们直接继承`AuthorizingRealm`(授权)，这样可以间接继承`Authentication`(身份认证)，和`CachingRealm`(缓存实现)

![Realm类图](https://image.kaelvihn.top/article/2024-01-04-2.png)

`Realm`的定义如下：

```java
public interface Realm {
    // 获取一个唯一的Realm的名字
    String getName();
	// 判断此Realm是否支持Token
    boolean supports(AuthenticationToken var1);
	// 根据Token获取认证信息
    AuthenticationInfo getAuthenticationInfo(AuthenticationToken var1) throws AuthenticationException;
}

```

> Realm的配置

1.**自定义Realm**

```java
/**
 * @author tuids
 * @date 2024/1/4 23:46
 */
public class MyRealm1 implements Realm {
    @Override
    public String getName() {
        return "MyRealm1";
    }

    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof UsernamePasswordToken;
    }

    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        // 获取用户名和密码
        String username = (String) token.getPrincipal();
        String password = new String((char[]) token.getCredentials());
        // 用户名错误 => 未知账户异常
        if (!"tuids".equals(username)) {
            throw new UnknownAccountException();
        }
        // 密码错误 => 凭证错误异常
        if ("123".equals(password)) {
            throw new IncorrectCredentialsException();
        }
        // 认证成功,返回一个AuthenticationInfo的实现
        return new SimpleAuthenticationInfo(username,password,getName());
    }
}
```

2. **ini文件配置自定义的Realm**

```ini
; 单Realm
; 声明一个Realm
myRealm1 = cn.tuids.myRealm1
; 指定SecurityManger的Realms实现
securityManger = $myRealm1


; 多Ream
myRealm1 = cn.tuids.myRealm1
myRealm2 = cn.tuids.myRealm2
securityManger = $myRealm1，$myRealm2
```

> JDBC Realm 使用

**依赖引入**

```xml
    <dependency>
        <groupId>com.alibaba</groupId>
        <artifactId>druid</artifactId>
        <version>42.6.0</version>
    </dependency>
    <dependency>
        <groupId>org.postgresql</groupId>
        <artifactId>postgresql</artifactId>
        <verson>1.2.8</verson>
     </dependency>
```

**创建数据库的sql脚本**

```sql
-- ------------------
-- TABLE USERS
-- ------------------
CREATE TABLE users(
                           user_id serial PRIMARY KEY,
                           username VARCHAR(32) NOT NULL,
                           password VARCHAR(32) NOT NULL,
                           password_salt VARCHAR(32) NOT NULL);

COMMENT ON TABLE users IS '用户表';
COMMENT ON COLUMN users.user_id IS '用户ID';
COMMENT ON COLUMN users.username IS '用户名';
COMMENT ON COLUMN users.password IS '用户密码';
COMMENT ON COLUMN users.password_salt IS '盐';
```

**shiro-jdbc-realm.ini**

```ini
jdbcRealm = org.apache.shiro.realm.jdbc.JdbcRealm
dataSource = com.alibaba.druid.pool.DruidDataSource
dataSource.driverClassName = org.postgresql.Driver
dataSource.url = jdbc:postgresql://localhost:3306/shiro
dataSource.username = root
\#dataSource.password = 123456
jdbcRealm.dataSource = $dataSource
securityManager.realms = $jdbcRealm
```

<mark>如果要使用JDBCRealm,数据库表名一定是users,用户名一定是username,因为JDBCRealm的源码如下:</mark>

```java
public class JdbcRealm extends AuthorizingRealm {
    protected static final String DEFAULT_AUTHENTICATION_QUERY = "select password from users where username = ?";
    protected static final String DEFAULT_SALTED_AUTHENTICATION_QUERY = "select password, password_salt from users where username = ?";
    protected static final String DEFAULT_USER_ROLES_QUERY = "select role_name from user_roles where username = ?";
    protected static final String DEFAULT_PERMISSIONS_QUERY = "select permission from roles_permissions where role_name = ?";
//--- snip ---
}
```

### Authenticator 及 AuthenticationStrategy

- `Authenticator`的职责是验证用户帐号，是**Shiro API**中身份验证核心的入口点：

```java
package org.apache.shiro.authc;

public interface Authenticator {
    AuthenticationInfo authenticate(AuthenticationToken var1) throws AuthenticationException;
}
```

如果验证成功，将返回**AuthenticationInfo**验证信息，该信息中包含了**身份**和**凭证**。如果验证失败将抛出**AuthenticationException**实现。

![Authenticator类图](https://image.kaelvihn.top/article/2024-01-08-1.png)

- `AuthenticationStrategy`的职责是配置验证时的验证规则。当然，Shiro也提供了默认的实现：***(默认是使用AtLeastOneSuccessfulStrategy)***

```java
public interface AuthenticationStrategy {
    // 在所有Realm认证前调用
    AuthenticationInfo beforeAllAttempts(Collection<? extends Realm> var1, AuthenticationToken var2) throws AuthenticationException;
	// 每一个Realm认证前调用
    AuthenticationInfo beforeAttempt(Realm var1, AuthenticationToken var2, AuthenticationInfo var3) throws AuthenticationException;
	// 每一个Realm认证后调用
    AuthenticationInfo afterAttempt(Realm var1, AuthenticationToken var2, AuthenticationInfo var3, AuthenticationInfo var4, Throwable var5) throws AuthenticationException;
	// Realm全部认证后调用
    AuthenticationInfo afterAllAttempts(AuthenticationToken var1, AuthenticationInfo var2) throws AuthenticationException;
}
```

- - `FirstSuccessfulStrategy`：只要有一个**Realm**验证成功即可，只返回第一个**Realm**身份认证信息。其他忽略
  - `AtLeastOneSuccessfulStrategy`：只要有一个**Realm**验证成功即可，但是与**FirstSuccessfulStrategy**不同的是，**AtLeastOneSuccessfulStrategy**会返回所有认证成功的**Realm**
  - `AllSuccessfulStrategy`：所有**Realm**验证成功才算成功，且返回所有**Realm**验证通过的信息

![AuthenticationStrategy类图](https://image.kaelvihn.top/article/2024-01-08-2.png)

> 简单使用

**配置ini文件(shiro-authenticator-all-success.ini)：**

```ini
; 指定securityManager的authenticator实现
authenticator = org.apache.shiro.authc.pam.ModularRealmAuthenticator
securityManager.authenticator = $authenticator
; 指定securityManager.authenticator的authenticationStrategy
allSuccessfulStrategy = org.apache.shiro.authc.pam.AllSuccessfulStrategy
securityManager.authenticator.authenticationStrategy = $allSuccessfulStrategy
; 配置Realm
myRealm1 = cn.tuids.MyRealm1
myRealm2 = cn.tuids.MyRealm2
myRealm3 = cn.tuids.MyRealm3
securityManager.realms=$myRealm1,$myRealm3
```

**代码示例：**

```java
/**
 * @author tuids
 * @date 2024/1/4 0:30
 */
public class ShiroApp {
    static Logger logger;

    static {
        BasicConfigurator.configure();
        logger = Logger.getLogger(ShiroApp.class);

    }

    @Test
    public void test() {
        login("classpath:shiro-authenticator-all-success.ini");
        // 获取验证成功的subject
        Subject subject = SecurityUtils.getSubject();
        //得到一个身份集合，其包含了Realm验证成功的身份信息
        PrincipalCollection principals = subject.getPrincipals();
        System.out.println("principals = " + principals);

    }

    private void login(String configFile) {
        // 创建SecurityManger工厂，此处使用Ini文件充当数据源来初始化SecurityManger
        IniSecurityManagerFactory securityManagerFactory = new IniSecurityManagerFactory(configFile);
        //创建对象实例，并绑定给SecurityUtils
        SecurityManager securityManager = securityManagerFactory.createInstance();
        SecurityUtils.setSecurityManager(securityManager);
        //得到Subject，创建username/password 验证 token
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("tuids", "123");
        try {
            //登录验证身份
            subject.login(token);
            logger.info("登录成功," + subject.isAuthenticated());
        } catch (AuthenticationException e) {
            //登录失败
            logger.error("登录失败,失败原因:" + e);
        }
    }
}
```

**输出结果：**

```
101 [main] ERROR cn.tuids.ShiroApp  - 登录失败,失败原因:org.apache.shiro.authc.IncorrectCredentialsException
principals = null
```

