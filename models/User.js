const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const saltRounds = 10

const userSchema = mongoose.Schema({
    name: {
        type: String,
        maslength: 50
    },
    email: {
        type: String,
        trim: true,
        unique: 1
    },
    password: {
        type: String,
        minlength: 5
    },
    lastname: {
        type: String,
        maxlength: 50
    },
    role: {
        type: Number,
        default: 0
    },
    image: String,
    token: {
        type: String
    },
    tokenExp: {
        type: Number
    }
})

userSchema.pre('save', function(next){

    var user = this;
    if(user.isModified('password')){
        // 비밀번호를 암호화 시킨다.
        bcrypt.genSalt(saltRounds, function(err, salt){
            if(err) return next(error)

            bcrypt.hash(user.password, salt, function(err, hash){
                if(err) return next(error)
                user.password = hash
                next()
            })
        })
    } else {
        next()
    }
})


userSchema.methods.comparePassword = function (plainPassword, cb){
    // plainPassword 1234567    암호화된 비밀번호 $2b$10$wBis7giFIxvrnBxA5CcWAOuwJ6xs6VaMgiM4RkkYo.KQm6WogPDjK
    // 암호화된 비밀번호를 다시 복호화 할 수 없음.
    // 따라서, plainPassword를 암호화하여 비교.
    bcrypt.compare(plainPassword, this.password, function(err, isMatch){
        if(err) return cb(err),
            cb(null, isMatch)
    })
}

const User = mongoose.model('User', userSchema)

module.exports = { User }