const ErrorHadler = require("../utils/ErrorHandler");
const catchAsyncErrors = require("./catchAsyncErrors");
const jwt = require("jsonwebtoken");
const User = require("../models/userModel");



exports.isAuthenticatedUser = catchAsyncErrors( async (req,res,next)=>{

    const { token } = req.cookies;

    if(!token){
        return next(new ErrorHadler("Please Login to access this resources",401));
    }

    const decodedData = jwt.verify(token,process.env.JWT_SECRET);

    req.user =  await User.findById(decodedData.id);
    next();
});


// Authorized Roles
exports.authorizeRoles = (...roles) =>{
    return (req,res,next)=>{

    if(!roles.includes(req.user.role)){
        return next( new ErrorHadler(
            `Role: ${req.user.role} is not allowed to access this resource`, 
             403
            )
            );
    }
    next();
    };
};