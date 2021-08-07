'use strict';

if (process.env.NODE_ENV != 'production') {
    require('dotenv').config();
}

var port = process.env.PORT || 1337;
console.log("Port: " + port);
//const { urlencoded } = require('express');
const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const flash = require('express-flash');
const session = require('express-session');
const { cache } = require('ejs');
const cookieParser = require('cookie-parser');
const methodOverride = require('method-override');
const fs = require('fs');


var users = JSON.parse(fs.readFileSync('users.json'));
console.log(users);

const getUserByEmail = email => users.find(user => user.email === email);
const getUSerById = id => users.find(user => user.id === id);

passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
    const user = getUserByEmail(email);
    if (user == null) {
        return done(null, false, { message: "No user with that email" });
    }

    try {
        if (await bcrypt.compare(password, user.password)) {
            return done(null, user);
        } else {
            return done(null, false, { message: "Password incorrect" });
        }
    } catch (e) {
        return done(e);
    }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => done(null, getUSerById(id)));

app.set('view-engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(flash());
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride('_method'));

app.get('/', (req, res) => {
    if (req.isAuthenticated()) {
        return res.render('index.ejs', { name: req.user.name, isAuthenticated: true });
    }
    res.render('index.ejs', { name: '', isAuthenticated: false });
    
});

app.get('/register', checkUserNotAuthenticated, (req, res) => {
    res.render('register.ejs');
});

app.post('/register', checkUserNotAuthenticated, async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        users.push({
            id: Date.now(),
            name: req.body.name,
            email: req.body.email,
            password: hashedPassword
        });
        //save new user to file
        fs.writeFileSync('users.json', JSON.stringify(users));
        console.log(users);
        res.redirect('/login');
        
    } catch (e) {
        res.redirect('/register');
    }
});

app.get('/login', checkUserNotAuthenticated, (req, res) => {
    res.render('login.ejs');
});

app.post('/login', checkUserNotAuthenticated, passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: 'login',
    failureFlash: true
}));

app.delete('/logout', (req, res) => {
    req.logOut();
    res.redirect('/login');
});

app.get('*', (req, res) => {
    res.send("<h1>404</h1><h1>Not found</h1>", 404);
})

function checkUserAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login');
}

function checkUserNotAuthenticated(req, res, next) {
    if (!req.isAuthenticated()) {
        return next();
    }
    res.redirect('/');
}

app.listen(port);