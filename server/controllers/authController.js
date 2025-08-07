import bcrypt from 'bcrypt'
// import { JsonWebTokenError } from 'jsonwebtoken';
import userModel from '../models/userModel.js';
import jwt from 'jsonwebtoken';
import transporter from '../config/nodemailer.js';
import { EMAIL_VERIFY_TEMPLATE, PASSWORD_RESET_TEMPLATE } from '../config/emailTemplate.js';


export const register= async (req, res) => {
    const {name, email, password} = req.body;
    if(!name || !email || !password){
        return res.json({success: false, message:"missing details"})
    }

    try {
        
        const existingUser = await userModel.findOne({email})
        if(existingUser){
            return res.json({success: false, message: "User already exists"})
        }
        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new userModel({name, email, password: hashedPassword});
        await user.save();

        const token = jwt.sign({id: user._id, }, process.env.JWT_SECRET, {expiresIn: '7d'});

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 *60*60*1000
        });

        //SENDING WELCOME EMAIL
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'Welcome to Authify',
            text: `Welcome to secure authentication system: Authify with email id ${email}`
        }

        await transporter.sendMail(mailOptions);

        return res.json({success: true});


    } catch(error){
        res.json({success: false, message: error.message})
    }
}

export const login = async(req, res) =>{
    const {email, password} = req.body;
    if(!email || !password){
        return res.json({success: false, message: 'Email and Password are required'})
    }

    try{
        const user = await userModel.findOne({email});

        if(!user){
            return res.json({success: false, message:' Invalid email'})
     }
     const isMatch = await bcrypt.compare(password, user.password);

     if(!isMatch){
        return res.json({success: false, message: 'Invalid password'})
     }

     const token = jwt.sign({id: user._id, }, process.env.JWT_SECRET, {expiresIn: '7d'});

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 *60*60*1000
        });


        return res.json({success: true});
    }
    catch(error){
        return res.json({success: false, message: error.message});
    }


}

export const logout = async(req, res) =>{
    try{
        res.clearCookie('token',{
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        })

        return res.json({success: true, message: 'Logged out'})
    }
    catch(error){
        return res.json({success: false, message: error.message});
    }
}


//SEND VERIFICATION OTP TO USERS MAIL
export const sendVerifyOtp = async(req, res) => {
    try{
        const {userId} = req.body;
        const user = await userModel.findById(userId);
        if (!user) {
            return res.json({success: false, message: "User not found"});
        }
        if(user.isAccountVerified){
            return res.json({success: false, message:"Account already verified"});
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));
        user.verifyOtp = otp;
        user.verifyOtpExpires = Date.now() + 24 * 60 * 60 * 1000;
        await user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account Verification OTP',
            // text: `Your OTP is ${otp}. Verify your account using this otp.`
            html: EMAIL_VERIFY_TEMPLATE.replace("{{otp}}", otp).replace("{{email}}", user.email)
        };

        await transporter.sendMail(mailOptions);
        res.json({success: true, message: "Verification OTP Sent on Email"});

    } catch(error){
        res.json({success:false, message: error.message});
    }
}

//VERIFY EMAIL USING OTP
export const verifyEmail = async (req, res) => {
    const {userId, otp} = req.body;
    if(!userId || !otp){
            return res.json({success: false, message:"missing details"})
    }

    try{
        const user = await userModel.findById(userId);
        if(!user){
            return res.json({success: false, message: 'User Not Found'});
        }
        if(user.verifyOtp ==='' || user.verifyOtp !== otp){
            return res.json({success: false, message: 'Invalid Otp'});

        }
        if(user.verifyOtpExpires < Date.now()){
            return res.json({success: false, message: 'Otp Expired'});
        }

        user.isAccountVerified = true;
        user.verifyOtp = '';
        user.verifyOtpExpires = 0;
        await user.save();
        return res.json({success: true, message: 'Email Verified Successfully'});


    } catch(error){
        res.json({success:false, message: error.message})
    }
}

//CHECK IF USER IS AUTHENTICATED

export const isAuthenticated = async (req, res) => {
    try{
        
        return res.json({success: true});
    } catch(error){
        res.json({success:false, message: error.message})
    }
}


//SEND PASSOWRD RESET OTP
export const sendResetOtp = async(req,res) => {
    const {email} = req.body;

    if(!email){
        return res.json({success: false, message:"email is required"})
    }
    try{
        const user = await userModel.findOne({email});
        if(!user){
            return res.json({success: false, message: 'User Not Found'});
        }

         const otp = String(Math.floor(100000 + Math.random() * 900000));
        user.resetOtp = otp;
        user.resetOtpExpires = Date.now() + 15 * 60 * 1000;
        await user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Password Reset OTP',
            // text: `Your OTP is ${otp}. For Reseting the Passoword`
            html: PASSWORD_RESET_TEMPLATE.replace("{{otp}}", otp).replace("{{email}}", user.email)
        };

        await transporter.sendMail(mailOptions);
        res.json({success: true, message: "Otp Sent to your email"});


    } catch(error){
        res.json({success:false, message: error.message})
    }
}
    
//RESET USER PASSWORD 
export const resetPassword = async(req, res) => {
    //otp, email and new pass
    const {email, otp, newPassword} = req.body;

    if(!email || !otp || !newPassword){
        return res.json({success: false, message: "Email, Otp and new Password are required"})
    }
    try{
        //find user using mail
        const user = await userModel.findOne({email});
        if(!user){
                return res.json({success: false, message: 'User Not Found'});

        }
        if(user.resetOtp === "" || user.resetOtp !== otp){
            return res.json({success: false, message: "Invalid Otp"})
        }

        if(user.resetOtpExpires < Date.now()){
            return res.json({success: false, message: "Otp Expired"})

        }

        //if otp is valid then update user password , encrypt and store new Password in db
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        user.resetOtp = "";
        user.resetOtpExpires = 0;

        await user.save();

        return res.json({success:true, message: "Password reset successfully"});
    } catch(error){
        res.json({success:false, message: error.message})
    }
}
