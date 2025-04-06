import validator from "validator";
import bcrypt from "bcrypt";
import userModel from "../models/userModel.js";
import jwt from "jsonwebtoken";

const createToken = (id) => {
    return jwt.sign({id},process.env.JWT_SECRET)
}
//route for user login
const loginUser = async (req,res)=>{
    try{
        const {email,password} = req.body;
        
        const user = await userModel.findOne({email});

        if (!user){
            return res.status(404).json({success:false,message:"User does not exist"})
        }

        const isMatch = await bcrypt.compare(password,user.password);

        if (isMatch){
            const token = createToken(user._id)
            res.status(200).json({success:true,token})
        }
        else{
            res.status(401).json({success:false,message:"Invalid Credentials"})
        }



    }catch(error){
        console.log(error);
        res.res.status(500).json({success:false,message:error.message})
    }



}

//Route for User Register
const registerUser = async (req,res)=>{
    try{
        const {name,email,password} = req.body;
        
        //checking if user already exists or not
        const exists = await userModel.findOne({email})
        if (exists){
            return res.res.status(400).json({success:false,message:"User already exists"})
        }

        //validating email format and strong password
        if (!validator.isEmail(email)){
            return res.res.status(400).json({success:false,message:"Please enter a valid email"})
        }
        if (password.length <8){
            return res.res.status(400).json({success:false,message:"Please Enter a strong Password"})    
        }

        //hashing user password
        const salt = await bcrypt.genSalt(10)
        const hashedPassword = await bcrypt.hash(password,salt)
        
        //create user and save it in database
        const newUser = new userModel({
            name:name,
            email:email,
            password:hashedPassword
        })

        const user = await newUser.save()

        const token = createToken(user._id)
        
        res.status(201).json({success:true,token})

    }catch(error){
        console.log(error)
        res.status(500).json({success:false,message:error.message})

    }
}

//Route for Admin Login
const adminLogin = async (req,res)=>{
    try{
        const {email,password} = req.body
        
        if (email === process.env.ADMIN_EMAIL && password === process.env.ADMIN_PASSWORD){
            const token = jwt.sign(email+password,process.env.JWT_SECRET);
            res.status(200).json({success:true,token})
        }else{
            res.status(401).json({success:false,message:"Invalid Credentials"})
        }

    }catch(error){
        res.status(500).json({success:false,message:error.message})
        
    }

}

export {loginUser,registerUser,adminLogin}