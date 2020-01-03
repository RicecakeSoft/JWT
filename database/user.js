const Mongoose      = require('mongoose');
const Moment        = require('moment');
const Crypto        = require('crypto');
const Schema        = Mongoose.Schema;

const schemaType    = new Schema
({
    email:              
    { 
        type:       String, 
        required:   true,
        unique:     true,
    },
    password:         
    { 
        type:       Buffer, 
        required:   [true, 'Password is required!'],
    },
    name:             
    { 
        type:       String, 
        required:   [true, 'Name is required!'],
    },
    class:             
    { 
        type:       String, 
        required:   [true, 'Class is required!'],
        default:    'guest',
    },
    token:            
    { 
        type:       Buffer,
        required:   [true, 'Token is required!'],
        default:    'null',
    },
    salt:
    {
        type:       Buffer, 
        required:   [true, 'salt is required!'], 
    },
    join_date:        
    { 
        type:       Date,
        required:   true, 
        default:    Date.now,
    },
    login_date:       
    { 
        type:       Date,
        required:   true, 
        default:    Date.now, 
    },
    login_count:       
    { 
        type:       Number,
        required:   true, 
        default:    0,
    },
});
schemaType.index({ id: 1 });
// Email Regex //
schemaType.path('email').validate(function (email) 
{
    const emailRegex = /\S+@\S+\.\S+/;
    return emailRegex.test(email);
 }, 'The e-mail field cannot be empty.');
// 유저 확인 //
schemaType.statics.findByEmail = function (email)
{
    const promise = new Promise((resolve, reject) =>
    {
        this.findOne({ email }).then(result =>
        {
            resolve(result);
        }).catch(() =>{ reject('findByEmail, Error'); });
    });
    return promise;
};
// 유저 토큰 확인 //
schemaType.statics.checkEmailNToken = function (email, token)
{
    const promise = new Promise((resolve, reject) =>
    {
        this.findOne({ email })
        .then(result =>
        {
            if (result) 
            {
                if      (result.token                     === JSON.stringify(token))      resolve(result);
                else if (JSON.stringify(result.token)     === token)                      resolve(result);
                else if (JSON.stringify(result.token)     === JSON.stringify(token))      resolve(result);
                else if (result.token.toString('base64')  === token.toString('base64'))   resolve(result);
                else                                                                      reject(null);
            }
            else reject(null);
        }).catch(() =>{ reject('checkEmailToken, Error'); });
    });
    return promise;
};
// 유저 등록 //
schemaType.methods.createUser = function ()
{
    const promise = new Promise((resolve, reject) =>
    {
        Crypto.randomBytes(64, (salterror, salt) => 
        {
            if (salterror) reject(salterror);
            else
            {
                this.salt = salt;
                // 암호화 비밀번호, 비밀번호에 붙일 salt, 암호화 반복 횟수, 비밀번호 길이, sha512 알고리즘  //
                Crypto.pbkdf2(this.password, this.salt.toString('base64'), 50505, 64, 'sha512', (sha512error, key) => 
                {
                    if (sha512error) reject(sha512error);
                    else
                    {
                        this.password = key;
                        this.save((error, result) => 
                        {
                            if (error)  reject(error);
                            else        resolve(result);
                        });
                    }
                });
            }
        });
    });
    return promise;                       
};
// 비밀번호 확인 //
schemaType.methods.comparePassword = function (password)
{
    const promise = new Promise((resolve, reject) =>
    {
        // 암호화 비밀번호, salt, 암호화 반복 횟수, 비밀번호 길이, sha512 알고리즘  //
        Crypto.pbkdf2(password, this.salt.toString('base64'), 50505, 64, 'sha512', (err, key) => 
        {
            if (this.password.toString('base64') === key.toString('base64'))    resolve(this);
            else                                                                reject(null);
        });
    });
    return promise;
};
// 토큰 생성 //
schemaType.methods.createToken = function ()
{    
    const promise = new Promise((resolve, reject) =>
    {
        const today         = new Date();
        const dateString    = `${today.getFullYear()}-${today.getMonth() + 1}-${today.getDate()}/${today.getHours()}:${today.getMinutes()}:${today.getSeconds()}.${today.getMilliseconds()}`;
        const token         = `${this.email}@${dateString}`;
        // 암호화 비밀번호, 비밀번호에 붙일 salt, 암호화 반복 횟수, 비밀번호 길이, sha512 알고리즘  //
        Crypto.pbkdf2(token, this.salt.toString('base64'), 50505, 64, 'sha512', (err, key) => 
        {
            this.token          = key.toString('base64');
            this.login_date     = Moment().utc("YYYY-MM-DD HH:mm:ss").toDate();
            this.save((err) => 
            {
                if (err)    reject(null);
                else        resolve(this);
            });
        });
    });
    return promise;
};
/// 유저 토큰 확인 //
schemaType.methods.checkToken = function (token)
{
    const promise = new Promise((resolve, reject) =>
    {
        if      (this.token                     === JSON.stringify(token))      resolve(this);
        else if (JSON.stringify(this.token)     === token)                      resolve(this);
        else if (JSON.stringify(this.token)     === JSON.stringify(token))      resolve(this);
        else if (this.token.toString('base64')  === token.toString('base64'))   resolve(this);
        else                                                                    reject(null);
    });
    return promise;
};
/// 유저 토큰 삭제 //
schemaType.methods.removeToken = function ()
{
    const promise = new Promise((resolve, reject) =>
    {
        this.token = ('null').toString('base64');
        this.save((saveerror, result) => 
        {
            if (saveerror)  reject(saveerror);
            else            resolve(result);
        });    
    });
    return promise;
};
// EXPORT //
module.exports = Mongoose.model('user', schemaType, 'user');