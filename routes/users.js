var express = require('express');
const userSchema = require('../models/newuser');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');
const session = require('express-session');
const parseurl = require('parseurl');
var router = express.Router();

/* GET users listing. */
router.get('/', function (req, res, next) {
  res.render('blog/auth');
});

router.get('/cookie', (req, res) => {
  res.cookie('drink', 'water');
  res.send('set cookies');
});
//정규 표현식.
//passport
router.use(
  session({
    secret: '12345',
    resave: false,
    saveUninitialized: true,
  })
);

router.use(function (req, res, next) {
  if (!req.session.views) {
    req.session.views = {};
  }

  // get the url pathname
  var pathname = parseurl(req).pathname;

  // count the views
  req.session.views[pathname] = (req.session.views[pathname] || 0) + 1;

  next();
});

router.get('/foo', function (req, res, next) {
  res.send('you viewed this page ' + req.session.views['/foo'] + ' times');
});

//not email. not form.
router.post(
  '/signup',
  body('email').isEmail().withMessage('아이디는 email 형태를 따르셔야 합니다.'),
  body('password')
    .isLength({ min: 5 })
    .withMessage('비밀번호는 최소 5글자 이상입니다.'),
  async (req, res) => {
    // 글 임의의ㅡ로직도
    // 넘오는값 post
    // id:email.psw:5글자 이상

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        errors: errors.array(),
      });
    }
    const email = req.body.email;
    const password = req.body.password;
    // 중복 가입.
    // 찾는 쿼리
    // 결과가 존재 => 중복으로 가입되어 있는 경우
    // 결과가 X => 신규가입.
    const findresult = await userSchema.findOne({ email: email });
    if (!findresult) {
      const salt = bcrypt.genSaltSync(10);
      const bcryptpw = bcrypt.hashSync(password, salt); //12345

      userSchema
        .create({
          email: email,
          password: bcryptpw,
        })
        .then((result) => {
          res.status(200).json(result);
        });
    } else {
      res.status(401).json({ msg: '이미 가입된 계정입니다.' });
    }
  }
);

router.post('/login', async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;
  const userdata = await userSchema.findOne({ email: email }).exec();
  if (!userdata) {
    return res.status(401).json({ msg: '가입되지 않은 계정입니다.' });
  } else {
    const pwMatch = bcrypt.compareSync(password, userdata.password);
    if (pwMatch) {
      res.status(200).json({ msg: 'OK' });
    } else {
      res.status(401).json({ msg: '비밀번호가 일치하지 않습니다.' });
    }
  }
});

router.get('/login', (req, res) => {
  res.render('blog/login');
});

/// 쿠키와 세션
/// 로그인 => id: abcd.
/// 쿠키 ===> 사용자의 브라우저에 저장 데이터 모음 => Jwt token => 정보 저장량 분산
/// 보안 이슈 문제로부터 자유로움
/// 쿠키로서 너의 정보를 너에게 저장. 그것이 잘못되는 것은 너의 책임.
/// 세션 ===> 서버쪽에 저장하는 데이터 모음 => session 많은 정보를 저장하게 됨.

module.exports = router;
