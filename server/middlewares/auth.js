// const jwt = require("jsonwebtoken");
// require("dotenv").config();
// const User = require('../models/User');

// // auth
// exports.auth = async (req, res, next) => {
//     try {

//         // Extract Token 
//         const token = req.cookies.token 
//                     || req.body.token 
//                     || req.header("Authorisation").replace("Bearer ", "");

        
//         // If token is missing, then return response
//         if(!token) {
//             return res.status(401).json({
//                 success: false,
//                 message: "Token is missing",
//             });
//         }

//         // verify the token 
//         try {
//             const decode = jwt.verify(token, process.env.JWT_SECRET);
//             console.log(decode);
//             req.user = decode;

//         } catch(error) {
//             return res.status(401).json({
//                 success: false,
//                 message: 'Token is invalid',
//             });
//         }
//         next();

//     } catch(error) {
//         return res.status(401).json({
//             success: false,
//             message: 'Something went wrong while validating the token',
//         });
//     }   
// }

// // isStudent
// exports.isStudent = async (req, res, next) => {

//     try {
//         if(req.user.accountType !== 'Student') {
//             return res.status(401).json({
//                 success: false,
//                 message: "This is a protected route for Students only",
//             });
//         }
//         next();
        
//     } catch(error) {
//         return res.status(500).json({
//             success: false,
//             message: "User role cannot be verified, Please try again",
//         });
//     }
// }

// // isInstructor
// const isInstructor = async (req, res, next) => {
//     try {
//         if(req.user.accountType !== 'Instructor') {
//             return res.status(401).json({
//                 success: false,
//                 message: "This is a protected route for Instructor only",
//             });
//         }
//         next();

//     } catch(error) {
//         return res.status(500).json({
//             success: false,
//             message: "User role cannot be verified, Please try again",
//         });
//     }
// }

// // isAdmin
// const isAdmin = async (req, res, next) => {
//     try {
//         if(req.user.accountType !== 'Admin') {
//             return res.status(401).json({
//                 success: false,
//                 message: "This is a protected route for Admin only",
//             });
//         } 
//         next();

//     } catch(error) {
//         return res.status(500).json({
//             success: false,
//             message: "User role cannot be verified, Please try again",
//         });
//     }   
// }



const jwt = require("jsonwebtoken");
const User = require("../models/User");
require('dotenv').config();


// Middleware to authenticate user
exports.auth = async (req, res, next) => {
    try {
        // extract token from cookies, body or headers
        const token = req.cookies.token || req.body.token || req.header("Authorization").replace("Bearer ", "");

        // if token is missing, return response
        if (!token) {
            return res.status(401).json({
                success: false,
                message: "Token is missing",
            });
        }

        // verify the token
        try {
            const decode = jwt.verify(token, process.env.JWT_SECRET);
            console.log(decode);
            req.user = decode;
        } catch (error) {
            return res.status(401).json({
                success: false,
                message: "Token is invalid",
            });
        }

        next();
          
    } catch (error) {

        return res.status(401).json({
            success: false,
            message: 'Something went wrong while validating the token',
        });
    }
}

// Middleware to check if user is a student
exports.isStudent = async (req, res, next) => {
    try {
         if (req.user.accountType !== "Student") {
            return res.status(401).json({
                success: false,
                message: "This is a protected route for Students only",  
            });
         }
         next();
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "User role cannot be verified, Please try again",
        });
    }
}

// Middleware to check if user is an instructor
exports.isInstructor = async (req, res, next) => {
    try {
        if (req.user.accountType !== "Instructor") {
            return res.status(401).json({
                success: false,
                message: "This is a protected route for Instructors only",
            });
        }
        next();
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "User role cannot be verified, Please try again",
        });
    }
}

// Middleware to check if user is an admin
exports.isAdmin = async (req, res, next) => {
    try {
        if (req.user.accountType !== "Admin") {
            return res.status(401).json({
                success: false,
                message: "This is a protected route for Admins only",
            });
        }
        next();
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "User role cannot be verified, Please try again",
        })
    }
}