CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    registration_date TIMESTAMP NOT NULL,
    login VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    password_setting_date TIMESTAMP NOT NULL,
    surname VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    patronymic VARCHAR(255) NOT NULL,
    phone VARCHAR(20),
    address VARCHAR(255)
);

CREATE TABLE permissions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL
);

CREATE TABLE Groups (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL
);

CREATE TABLE groups_permissions (
    id SERIAL PRIMARY KEY,
    group_id INT REFERENCES groups(id) NOT NULL,
    permission_id INT REFERENCES permissions(id) NOT NULL,
    CONSTRAINT UC_Groups_Permissions UNIQUE (group_id, permission_id),
    CONSTRAINT FK_Groups_Permissions_Group FOREIGN KEY (group_id) REFERENCES groups(id),
    CONSTRAINT FK_Groups_Permissions_Permission FOREIGN KEY (permission_id) REFERENCES permissions(id)
);

ALTER TABLE users
ADD COLUMN group_id INT REFERENCES groups(id);

CREATE TABLE refresh_tokens (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) NOT NULL,
    token VARCHAR(255) NOT NULL,
    expires TIMESTAMP NOT NULL,
    revoked TIMESTAMP,
    CONSTRAINT UC_RefreshTokens UNIQUE (token),
    CONSTRAINT FK_RefreshTokens_User FOREIGN KEY (user_id) REFERENCES users(id)
);