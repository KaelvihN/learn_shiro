-- ------------------
-- TABLE SHIRO_USER
-- ------------------
CREATE TABLE shiro_user(
                           user_id serial PRIMARY KEY,
                           username VARCHAR(32) NOT NULL,
                           password VARCHAR(32) NOT NULL,
                           salt VARCHAR(32) NOT NULL);

COMMENT ON TABLE shiro_user IS '用户表';
COMMENT ON COLUMN shiro_user.user_id IS '用户ID';
COMMENT ON COLUMN shiro_user.username IS '用户名';
COMMENT ON COLUMN shiro_user.password IS '用户密码';
COMMENT ON COLUMN shiro_user.salt IS '盐';


-- -----------------
-- TABLE SHIRO_ROLE
-- -----------------
CREATE TABLE shiro_role(
                           role_id serial PRIMARY KEY,
                           role_name VARCHAR(32) NOT NULL
);

COMMENT ON TABLE shiro_role IS '角色表';
COMMENT ON COLUMN shiro_role.role_id IS '角色id';
COMMENT ON COLUMN shiro_role.role_name IS '角色名称';


-- -----------------------
-- TABLE SHIRO_PERMISSION
-- -----------------------
CREATE TABLE shiro_permission(
                                 permission_id serial PRIMARY KEY,
                                 permission_name VARCHAR(32) NOT NULL
);

COMMENT ON TABLE shiro_permission IS '权限表';
COMMENT ON COLUMN shiro_permission.permission_id IS '权限id';
COMMENT ON COLUMN shiro_permission.permission_name IS '权限名称';


-- ----------------
-- SHIRO_USER_ROLE
-- ----------------
CREATE TABLE shiro_user_role(
                                user_id INT NOT NULL,
                                role_id INT NOT NULL
);

COMMENT ON TABLE shiro_permission IS '用户-角色表';
COMMENT ON COLUMN shiro_user_role.user_id IS '用户id';
COMMENT ON COLUMN shiro_user_role.role_id IS '角色id';

-- ---------------------
-- SHIRO_ROLE_PERMISSION
-- ----------------------
CREATE TABLE shiro_role_permission(
                                role_id INT NOT NULL,
                                permission_id INT NOT NULL
);

COMMENT ON TABLE shiro_role_permission IS '角色-权限表';
COMMENT ON COLUMN shiro_role_permission.role_id IS '角色id';
COMMENT ON COLUMN shiro_role_permission.permission_id IS '权限id';

