import jwt from "jsonwebtoken"

const adminAuth = async (req,res,next)=>{
    try{
        const token = req.headers.authorization?.split(" ")[1]; // Extract Bearer Token
        if (!token){
            return res.status(401).json({success:false,message:"not authorized"})
        }
        const token_decode = jwt.verify(token,process.env.JWT_SECRET);
        
        if (token_decode !== process.env.ADMIN_EMAIL + process.env.ADMIN_PASSWORD){
            return res.status(403).json({success:false,message:"Not authorized login"})
        }
        next();

    }catch(error){
        console.log(error)
        res.status(500).json({success:false,message:error.message})

    }
}

export default adminAuth