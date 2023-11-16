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

-- Вставка данных в таблицу permissions
INSERT INTO permissions (name) VALUES ('Добавить пользователя');
INSERT INTO permissions (name) VALUES ('Удалить пользователя');
INSERT INTO permissions (name) VALUES ('Изменить пользователя');
INSERT INTO permissions (name) VALUES ('Просмотреть пользователя');
INSERT INTO permissions (name) VALUES ('Добавить Гео объект');
INSERT INTO permissions (name) VALUES ('Удалить Гео объект');
INSERT INTO permissions (name) VALUES ('Изменить Гео объект');

INSERT INTO user_permissions (user_id, permission_id)
VALUES (6, 5);

UPDATE users
SET is_blocked = false
WHERE id = 6;

CREATE OR REPLACE FUNCTION geolens_authentication(_identifier text)
    RETURNS TABLE (
        id int,
        email text,
        login text,
        is_blocked boolean,
        address text,
        phone varchar(20),
        patronymic text,
        name text,
        surname text,
        password text,
        password_updated timestamp,
        registration_date timestamp
    )
LANGUAGE SQL
AS $$
    SELECT
        us.id,
        us.email,
        us.login,
        us.is_blocked,
        us.address,
        us.phone,
        us.patronymic,
        us.name,
        us.surname,
        us.password,
        us.password_updated,
        us.registration_date
    FROM
        users us
    WHERE
        us.login = _identifier OR us.email = _identifier;
$$;


CREATE OR REPLACE PROCEDURE geolens_registration(
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
    RETURNS TABLE (
        id INT,
        email TEXT,
        login TEXT,
        is_blocked BOOLEAN,
        address TEXT,
        phone VARCHAR(20),
        patronymic TEXT,
        name TEXT,
        surname TEXT,
        password TEXT,
        password_updated TIMESTAMP,
        registration_date TIMESTAMP
    )
    LANGUAGE SQL
AS $$
    SELECT
        us.id,
        us.email,
        us.login,
        us.is_blocked,
        us.address,
        us.phone,
        us.patronymic,
        us.name,
        us.surname,
        us.password,
        us.password_updated,
        us.registration_date
    FROM
        USERS us
    WHERE
        us.id = (SELECT user_id FROM  refresh_tokens WHERE refresh_token = _refresh_token);
$$;


CREATE OR REPLACE FUNCTION get_user_permissions(_user_id INT)
RETURNS SETOF INT
LANGUAGE SQL
AS $$
    SELECT permission_id FROM user_permissions WHERE user_id = _user_id;
$$;

CREATE OR REPLACE PROCEDURE add_refresh_token(
    _user_id INT,
    _refresh_token text,
    _expires timestamp without time zone)
LANGUAGE SQL
AS $$
    INSERT INTO refresh_tokens (user_id, refresh_token, expires)
    VALUES (_user_id, _refresh_token, _expires);
$$;

CREATE OR REPLACE PROCEDURE delete_refresh_token(
    _refresh_token text)
LANGUAGE SQL
AS $$
    DELETE FROM refresh_tokens WHERE refresh_token = _refresh_token;
$$;

CREATE OR REPLACE FUNCTION exists_user_by_login(_login text)
RETURNS BOOLEAN
LANGUAGE SQL
AS $$
    SELECT EXISTS (SELECT 1 FROM users WHERE login = _login);
$$;

CREATE OR REPLACE FUNCTION exists_user_by_user_id(_user_id int)
RETURNS BOOLEAN
LANGUAGE SQL
AS $$
    SELECT EXISTS (SELECT 1 FROM users WHERE id = _user_id);
$$;

CREATE OR REPLACE FUNCTION is_valid_refresh_token(_refresh_token text)
    RETURNS BOOLEAN
    LANGUAGE SQL
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM refresh_tokens
        WHERE refresh_token = _refresh_token
          AND expires > NOW()
    );
$$;

CREATE OR REPLACE PROCEDURE geolens_block_user(_user_id INT)
LANGUAGE SQL
AS $$
    UPDATE users SET is_blocked = true WHERE id = _user_id;
$$;