package cn.tuids;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;

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
