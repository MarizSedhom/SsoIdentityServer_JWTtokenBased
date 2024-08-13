# Customized SSO Server with JWT-Based Authorization

This project is a customized Single Sign-On (SSO) server built using ASP.NET , providing JWT-based authentication and authorization. The SSO server allows clients to authenticate users and validate their roles using JSON Web Tokens (JWTs).

## Features

- **Custom SSO Implementation**: No external packages like IdentityServer4 or Duende are used; everything is built from scratch.
- **JWT-Based Authentication**: Users are authenticated using JWT tokens, which are issued upon successful login or registration.
- **Role-Based Authorization**: Roles are assigned to users, and specific pages can be accessed based on the user's role (e.g., Admin, User).
- **Shared Cookie Across Client Apps**: The JWT token is stored in a secure cookie, allowing for seamless authentication between the SSO server and client applications.
- **User Claims and Roles**: User claims, including roles, are embedded within the JWT token, ensuring secure and scalable role-based access control.
