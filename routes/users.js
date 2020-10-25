const express=require('express');
const router=express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');

//login page
//user model
const User = require('../models/User')

router.get('/login',(req,res)=>res.render('login'))

//Register page
router.get('/register',(req,res)=>res.render('register'));

//Register Handle
router.post('/register',(req,res)=>{
    const { name, email, password , password2 } = req.body
    let errors = [] ;
    
    //check required fields
    if(!name || !email || !password || !password2){
        errors.push({ msg : 'Please fill all the fields.' })
    }

    //check password match
    if(password !== password2){
        errors.push({ msg : 'Passwords do not match'})
    }

    //check password length 
    if(password.length < 6){
        errors.push({ msg: 'Passwords should be of 6 characters'})
    }
    if(errors.length > 0) {
        res.render('register',{
            errors,
            name,
            email,
            password,
            password2
        })
    }else{
    //    res.send('password')
        User.findOne({ email:email }).then(user =>{
            if(user){
                //user exist
                errors.push({ msg : 'Email is already registered'})
                res.render('register',{
                    errors,
                    name,
                    email,
                    password,
                    password2
                
                })
            }else{
                const newUser = new User({
                    name,
                    email,
                    password
                });


                //Hash Password : bcrypt has a method called gensalt
                bcrypt.genSalt(10 , (err,salt)=>{
                    bcrypt.hash( newUser.password, salt ,(err,hash)=>{
                        if(err) throw err

                        //set password to hashed
                        newUser.password = hash;
                        //save User
                        newUser.save()
                        .then(user => {
                            req.flash('success_msg','You are now registered. Now you can log in')
                            res.redirect('/users/login')
                        })
                        .catch(err => console.log(err))
                    })
                })
            }
            
           
        })
    }


})
//login handle 
//passport docs : custom callback
router.post('/login',(res,req,next)=>{
    passport.authenticate('local',{
        successRedirect : '/dashboard',
        failureRedirect : '/users/login',
        failureFlash : true
    })(req,res,next);
})

module.exports=router;