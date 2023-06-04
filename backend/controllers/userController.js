const ErrorHadler = require("../utils/ErrorHandler");
const catchAsyncErrors = require("../middleware/catchAsyncErrors");
const User = require("../models/userModel");
const sendToken = require("../utils/jwtToken");
const { validate } = require("../models/userModel");
const sendEmail = require("../utils/sendEmail");
const crypto = require("crypto");


// Resgister a User
exports.registerUser = catchAsyncErrors( async(req,res,next)=>{

    const {name,email,password} = req.body;

    const user = await User.create({
        name,email,password,
        avatar: {
            public_id: "this is a sample id",
            url: "profilepicurl",
        },
    });

    // const token = user.getJWTToken();

    // res.status(201).json({
    //     success: true,
    //     token,
    // });
    sendToken(user,201,res);
});



// Login User
exports.loginUser = catchAsyncErrors (async (req,res,next)=>{

    const {email,password} = req.body;

    // Checking if user has given password and email both

    if(!email || !password){
        return next(new ErrorHadler("Please Enter Email & Password", 400));
    }

    const user = await User.findOne({ email }).select("+password");

    if(!user){
        return next(new ErrorHadler("Invalid email or password", 401));
    }

    const isPasswordMatched = await user.comparePassword(password);

    if(!isPasswordMatched){
        return next(new ErrorHadler("Invalid email or password", 401));
    }

    sendToken(user,200,res);
 });



//  Logout User
exports.logout = catchAsyncErrors( async(req,res,next)=>{

    res.cookie("token", null,{
        expires:new Date(Date.now()),
        httpOnly: true,
    });

    res.status(200).json({
        success:true,
        message:"Logged Out",
    });
});


// Forgot Password
exports.forgotPassword = catchAsyncErrors(async(req,res,next)=>{

    const user = await User.findOne({email:req.body.email});

    if(!user){
        return next(new ErrorHadler("User not found", 404));
    }

    // Get ResetPassword Token
    const resetToken = user.getResetPasswordToken();

    await user.save({ validateBeforeSave: false });
 
    const resetPasswordUrl = `${req.protocol}://${req.get("host")}/api/v1/password/reset/${resetToken}`;

    const message = `your password reset token is ;- \n\n ${resetPasswordUrl} \n\n If you have not requested this email then please ignore it `;

    try {

        await sendEmail({
            email:user.email,
            subject:`Ecommerce Password Recovery`,
            message,
        });

        res.status(200).json({
            success:true,
            message: `Email send to ${user.email} successfully`,
        })
        
    } catch (error) {
        user.resetPasswordToken = undefined;
        user.resetPasswordExpire = undefined;

        await user.save({ validateBeforeSave: false });

        return next(new ErrorHadler(error.message, 500));
    }
});



    // Reset Password
exports.resetPassword = catchAsyncErrors(async(req,res,next)=>{

    // creating token hash
    const resetPasswordToken = crypto.createHash("sha256").update(req.params.token).digest("hex");

    const user = await User.findOne({
        resetPasswordToken,
        resetPasswordExpire: {$gt: Date.now() },
    });

    if(!user){
        return next(new ErrorHadler("Reset Password Token is invalid or has been expired", 400));
    }

    user.password = req.body.password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;

    await user.save();

    sendToken(user, 200, res);

});



// Get User Details
exports.getUserDetails = catchAsyncErrors(async(req, res, next) => {
 
    const user = await User.findById(req.user.id);

    res.status(200).json({
        success: true,
        user,
    });
});


// Update User Password
exports.updatePassword = catchAsyncErrors(async(req,res,next)=>{

    const user = await User.findById(req.user.id).select("+password");

    const isPasswordMatched = await user.comparePassword(req.body.oldPassword);

    if(!isPasswordMatched){
        return next(new ErrorHadler("old  password is incorrect", 400));
    }

    if(req.body.newPassword !==req.body.confirmPassword){
        return next(new ErrorHadler("Password does not match", 400));
    }

    user.password = req.body.newPassword;
    await user.save();

    sendToken(user, 200, res);
});




// Update User Profile
exports.updateProfile = catchAsyncErrors(async(req,res,next)=>{

   
    const newUserData = {
        name:req.body.name,
        email:req.body.email,
    }

    // we will add cloudinary later

    const user = await User.findByIdAndUpdate(req.user.id, newUserData, {
        new: true,
        runValidators: true,
        useFindAndModify: false,
    });

    res.status(200).json({
        success:true,
    });
});


// Get All Users --Admin
exports.getAllUser = catchAsyncErrors(async(req,res,next)=>{
    const users = await User.find();

    res.status(200).json({
        success: true,
        users,
    });
});

// Get Single User --Admin
exports.getSingleUser = catchAsyncErrors(async(req,res,next)=>{
    const user = await User.findById(req.params.id);

    if(!user){
        return next(new ErrorHadler(`User does not exits with ID: ${req.params.id}`));
    }

    res.status(200).json({
        success: true,
        user,
    });
});




// Update User Roles --Admin
exports.updateUserRole = catchAsyncErrors(async(req,res,next)=>{

   
    const newUserData = {
        name:req.body.name,
        email:req.body.email,
        role:req.body.role,
    }


    const user = await User.findByIdAndUpdate(req.params.id, newUserData, {
        new: true,
        runValidators: true,
        useFindAndModify: false,
    });

    res.status(200).json({
        success:true,
    });
});



// Delete User -- Admin
exports.deleteUser = catchAsyncErrors(async(req,res,next)=>{

   const user = await User.findById(req.params.id);
    // we will remove  cloudinary later

    if(!user){
        return next(new ErrorHadler(`User does not exits with Id: ${req.params.id}`));
    }

    await user.remove();

    res.status(200).json({
        success:true,
        message:"User Deleted Successfully",
    });
});