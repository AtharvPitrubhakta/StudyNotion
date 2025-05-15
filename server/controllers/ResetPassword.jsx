const User = require("../models/User");
const mailSender = require("../utils/mailSender");
const bcrypt = require("bcrypt");

// Reset password token generation
// This function generates a reset password token and sends it to the user's email
exports.resetPasswordToken = async (req, res) => {
  try {
    // get email from request body
    const { email } = req.body;

    // check if user with this email exists if not return response and other email validations
    const user = await User.findOne({ email: email });
    if (!user) {
      return res.json({
        success: false,
        message: "Your email is not registered with us",
      });
    }

    // generate token and update user with token and expiration time
    const token = crypto.randomUUID();

    // update user by adding token and expiration time
    const updatedDetails = await User.findOneAndUpdate(
      { email: email },
      {
        token: token,
        resetPasswordExpires: Date.now() + 5 * 60 * 1000,
      },
      { new: true } // return new updated document
    );

    // create url with token
    const url = `http://localhost:3000/update-password/${token}`;

    // send mail containing the url
    await mailSender(
      email,
      "Password Reset Link",
      `Password Reset Link: ${url}`
    );

    // return response
    return res.status(200).json({
      success: true,
      message:
        "Email sent successfully, Please check email and change password",
    });
    
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      success: false,
      message: "Something went wrong while sending reset password mail",
    });
  }
};

// Reset password
// This function resets the password of the user
exports.resetPassword = async (req, res) => {
    try {
        // data fetch from req body
        const { password, confirmPassword, token } = req.body;

        // validation
        if (password !== confirmPassword) {
            return res.json({
                success: false,
                message: "Password not matching",
            });
        }

        // get user details from db using token
        const userDetails = await User.findOne( {token: token} ); 

        // if no entry - invalid token
        if (!userDetails) {
            return res.json({
                success: false,
                message: "Token is invalid",
            });
        }

        // check if token is expired
        if (userDetails.resetPasswordExpires < Date.now()) {
            return res.json({
                success: false,
                message: "Token is expired, Please regenerate your token",
            });
        }

        // hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // password update
        await User.findOneAndUpdate(
            // searching criteria
            { token: token },
            // updation criteria (which value is updated)
            { password: hashedPassword },
            // return new/updated document
            { new: true }
        )

        // return response
        return res.status(200).json({
            success: true,
            message: "Password reset successful",
        });
    } 
    catch (error) {
      console.log(error);
      return res.status(500).json({
        success: false,
        message: "Something went wrong while resetting password",
      });
    }
}