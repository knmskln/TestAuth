create table public.users
(
    id                serial
        primary key,
    registration_date timestamp    not null,
    login             varchar(255) not null
        constraint login_users_pk
            unique,
    password          varchar(255) not null,
    password_updated  timestamp    not null,
    surname           varchar(255) not null,
    name              varchar(255) not null,
    patronymic        varchar(255),
    phone             varchar(20),
    address           varchar(255),
    is_blocked        boolean      not null,
    email             varchar(255) not null
        constraint email_users_pk
            unique
);
 
create table public.permissions
(
    id   serial
        primary key,
    name varchar(255) not null
);
 
create table public.groups
(
    id   serial
        primary key,
    name varchar(255) not null
);
 
create table public.user_groups
(
    group_id integer not null
        constraint user_groups_groups_id_fk
            references public.groups,
    user_id  integer not null
        constraint user_groups_users_id_fk
            references public.users
);
 
create table public.refresh_tokens
(
    user_id       integer   not null
        constraint refresh_tokens_users_id_fk
            references public.users,
    refresh_token text      not null
        constraint refresh_tokens_pk
            unique,
    expires       timestamp not null
);
 
create table public.user_permissions
(
    permission_id integer not null
        constraint user_permissions_permissions_id_fk
            references public.permissions,
    user_id       integer
        constraint user_permissions_users_id_fk
            references public.users
);

create table public.group_permissions
(
    group_id      integer not null
        constraint group_permissions_groups_id_fk
            references public.groups,
    permission_id integer not null
        constraint group_permissions_permissions_id_fk
            references public.permissions
);

-- Вставка данных в таблицу groups
INSERT INTO groups (name) VALUES ('Работа с картой');
INSERT INTO groups (name) VALUES ('Работа с пользователями');

-- Вставка данных в таблицу permissions
INSERT INTO permissions (name) VALUES ('Добавить пользователя');
INSERT INTO permissions (name) VALUES ('Удалить пользователя');
INSERT INTO permissions (name) VALUES ('Изменить пользователя');
INSERT INTO permissions (name) VALUES ('Просмотреть пользователя');
INSERT INTO permissions (name) VALUES ('Добавить Гео объект');
INSERT INTO permissions (name) VALUES ('Удалить Гео объект');
INSERT INTO permissions (name) VALUES ('Изменить Гео объект');

INSERT INTO group_permissions (group_id, permission_id)
SELECT
    (SELECT id FROM groups WHERE name = 'Работа с пользователями'),
    id
FROM permissions
WHERE name IN ('Добавить пользователя', 'Удалить пользователя', 'Изменить пользователя', 'Просмотреть пользователя');

INSERT INTO group_permissions (group_id, permission_id)
SELECT
    (SELECT id FROM groups WHERE name = 'Работа с картой'),
    id
FROM permissions
WHERE name IN ('Добавить Гео объект', 'Удалить Гео объект', 'Изменить Гео объект');

INSERT INTO user_groups (user_id, group_id)
VALUES (1, 2);

INSERT INTO user_permissions (user_id, permission_id)
VALUES (1, 2);

UPDATE users
SET is_blocked = true
WHERE id = 5;

CREATE OR REPLACE FUNCTION geolens_custom_auth(identifier text)
    RETURNS SETOF users
LANGUAGE SQL
AS $$
    SELECT * FROM users us
    WHERE us.login = identifier OR us.email = identifier;
$$;

CREATE OR REPLACE PROCEDURE geolens_custom_reg(
    _email text,
    _login text,
    _is_blocked boolean,
    _address text,
    _phone varchar(20),
    _patronymic text,
    _name text,
    _surname text,
    _password text,
    _password_updated timestamp,
    _registration_date timestamp)
LANGUAGE SQL
AS $$
    INSERT INTO users (email, login, is_blocked, address, phone, patronymic, name, surname, password, password_updated, registration_date)
    VALUES (_email, _login, _is_blocked, _address, _phone, _patronymic, _name, _surname, _password, _password_updated, _registration_date);
$$;

CREATE OR REPLACE FUNCTION get_user_by_refresh_token(_refresh_token text)
	RETURNS SETOF users					
LANGUAGE SQL
AS $$
	SELECT * FROM USERS us
	WHERE us.id = (SELECT user_id FROM  refresh_tokens WHERE refresh_token = _refresh_token)
$$;

CREATE OR REPLACE FUNCTION get_user_permissions(_user_id INT)
RETURNS SETOF INT
LANGUAGE SQL
AS $$
    SELECT permission_id FROM user_permissions WHERE user_id = _user_id;
$$;