// package com.network.security.services;

// import com.network.security.Dao.UserDao;
// import com.network.security.entity.User;
// import com.network.security.util.PasswordUtils;

// public class UserService {
//     private final UserDao userDao;

//     public UserService(UserDao dao) {
//         this.userDao = dao;
//     }

//     public void registerUser(String username, String password, String role) throws Exception {
//         String hash = PasswordUtils.hashPassword(password);
//         User user = new User(username, hash, Enum.valueOf(com.network.security.entity.Role.class, role.toUpperCase()));
//         userDao.createUser(user);
//     }

//     public boolean validateLogin(String username, String password) throws Exception {
//         User user = userDao.getUserByUsername(username);
//         if (user == null) return false;
//         return PasswordUtils.hashPassword(password).equals(user.getPasswordHash());
//     }

//     public User getUser(String username) throws Exception {
//         return userDao.getUserByUsername(username);
//     }
// }
