CREATE DATABASE authenticated_users;

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    OTP VARCHAR(255) NOT NULL,
    profile_picture VARCHAR(255)
);

