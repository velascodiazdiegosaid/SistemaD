
const bcrypt = require('bcrypt');


function index(req, res) {
  if (req.session.loggedin) {
    res.redirect('/');
  } else {
    res.render('login/index');
  }
}

function register(req, res) {
  if (req.session.loggedin) {
    res.redirect('/');
  } else {
    res.render('login/register');
  }
  
}

function storeUser(req,res){
  const data=req.body;
  req.getConnection((err,conn) => {
    conn.query('SELECT * FROM users WHERE email= ?',[data.email], (err,userData) => {
      if (userData.length>0){
        res.render('login/register', {error: 'User already exists'});
      } else {
        bcrypt.hash(data.password, 12).then(hash => {
          console.log(hash);
          data.password=hash;
          //console.log(data);
          req.getConnection((err,conn) => {
              conn.query('INSERT INTO users SET ?',[data], (err,rows) => {
                res.redirect('/'); 
              });
          });
      
        });
      }
    });
  });
} 


function auth(req, res) {
  const data = req.body;
	//let email = req.body.email;
	//let password = req.body.password;

  req.getConnection((err, conn) => {
    conn.query('SELECT * FROM users WHERE email = ?', [data.email], (err, userData) => {
      if(userData.length > 0) {
        userData.forEach(element => {
          bcrypt.compare(data.password,element.password, (err,isMatch) => {
            if(!isMatch){
              console.log("out",userData);
              res.render('login/index', {error: 'Error password or email do not exist!'});
            } else {
              console.log("wellcome");
              req.session.loggedin = true;
              req.session.name = element.name;
              res.redirect('/');
            }
          });   
        });     







      } else {
        res.render('login/index', {error: 'Error password or email do not exist!'});
      }    
    });
  });
}

function logout(req, res) {
  if (req.session.loggedin) {
    req.session.destroy();
  }
  res.redirect('/');
}


module.exports = {
  index: index,
  register: register,
  auth: auth,
  logout: logout,
  storeUser: storeUser,

}

