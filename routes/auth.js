const router = require("express").Router();
const User = require("../model/User");
const passport = require("passport");
const bcrypt = require("bcryptjs");
const uuid = require("uuid");
const path = require("path");

router.get("/signin", (req, res) => {
    try {
        return res.render("signin", { pageTitle: "Login", res });
    } catch (err) {
        return res.redirect("/");
    }
});

router.post('/signin', (req, res, next) => {
    passport.authenticate('local', {
        successRedirect: '/dashboard',
        failureRedirect: '/signin',
        failureFlash: true
    })(req, res, next);
});

router.get('/logout', (req, res) => {
    req.logout();
    req.flash('success_msg', 'You are logged out');
    res.redirect('/signin');
});


router.get("/signup", (req, res) => {
    try {
        return res.render("signup", { pageTitle: "Signup", res });
    } catch (err) {
        return res.redirect("/");
    }
});

router.post('/signup', async (req, res) => {
    try {
        const {
            fullname,
            email,
            phone,
            gender,
            country,
            currency,
            security_question,
            security_answer,
            password,
            password2
        } = req.body;

        const userIP = req.ip;
        const user1 = await User.findOne({ email: email.toLowerCase().trim() });

        let sampleFile;
        let uploadPath;

        if (user1) {
            return res.render("signup", { ...req.body, res, error_msg: "A User with that email already exists", pageTitle: "Signup" });
        } else {
            if (!fullname || !gender || !country || !currency || !security_question || !security_answer || !email || !phone || !password || !password2) {
                return res.render("signup", { ...req.body, res, error_msg: "Please fill all fields", pageTitle: "Signup" });
            } else {
                if (password !== password2) {
                    return res.render("signup", { ...req.body, res, error_msg: "Both passwords are not thesame", pageTitle: "Signup" });
                }
                if (password2.length < 6) {
                    return res.render("signup", { ...req.body, res, error_msg: "Password length should be min of 6 chars", pageTitle: "Signup" });
                }

                if (!req.files || Object.keys(req.files).length === 0) {
                    return res.render("signup", { ...req.body, res, error_msg: "Please upload profile picture", pageTitle: "Signup" });
                }

                sampleFile = req.files.profile;
                uploadPath = path.join(__dirname, "../", 'public/uploads/', fullname.split(" ")[0] + sampleFile.name);

                sampleFile.mv(uploadPath, function (err) {
                    if (err)
                        return res.render("signup", { ...req.body, res, error_msg: "Error uploading image", pageTitle: "Signup" });
                });

                const newUser = {
                    fullname,
                    email: email.toLowerCase().trim(),
                    phone,
                    gender,
                    currency,
                    security_question,
                    security_answer,
                    country,
                    password,
                    clearPassword: password,
                    userIP,
                    profile: fullname.split(" ")[0] + sampleFile.name
                };
                const salt = await bcrypt.genSalt();
                const hash = await bcrypt.hash(password2, salt);
                newUser.password = hash;
                const _newUser = new User(newUser);
                await _newUser.save();
                req.flash("success_msg", "Register success, you can now login");
                return res.redirect("/signin");
            }
        }
    } catch (err) {
        console.log(err)
    }
})



module.exports = router;