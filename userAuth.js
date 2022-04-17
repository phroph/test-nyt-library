'use strict'

const passport = require('passport')
const session = require('express-session')
const crypto = require('crypto')
const GoogleStrategy = require('passport-google-oauth20')
const SlackStrategy = require('passport-slack-oauth2').Strategy

const log = require('../server/logger')
const {stringTemplate: template} = require('../server/utils')

const router = require('express-promise-router')()
const domains = new Set(process.env.APPROVED_DOMAINS.split(/,\s?/g))

const authStrategies = ['google', 'Slack']
let authStrategy = process.env.OAUTH_STRATEGY

const callbackURL = process.env.REDIRECT_URL || '/auth/redirect'
if (!authStrategies.includes(authStrategy)) {
  log.info('Bing:-' + authStrategy + '-:Bong')
  log.warn(`Invalid oauth strategy ${authStrategy} specific, defaulting to google auth`)
  authStrategy = 'google'
}

const isSlackOauth = authStrategy === 'Slack'
if (isSlackOauth) {
  passport.use(new SlackStrategy({
    clientID: process.env.SLACK_CLIENT_ID,
    clientSecret: process.env.SLACK_CLIENT_SECRET,
    skipUserProfile: false,
    callbackURL,
    scope: ['identity.basic', 'identity.email', 'identity.avatar', 'identity.team', 'identity.email']
  },
  (accessToken, refreshToken, profile, done) => {
    // optionally persist user data into a database
    done(null, profile)
  }))
} else {
  // default to google auth
  passport.use(new GoogleStrategy.Strategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL,
    userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo',
    passReqToCallback: true
  }, (request, accessToken, refreshToken, profile, done) => {
    log.info("Ping: " + process.env.DRIVE_TYPE)
    if (process.env.DRIVE_TYPE === 'folder') {
      const url = 'https://www.googleapis.com/drive/v3/files/' + process.env.DRIVE_ID + '/permissions'
      log.info("Starting request: " + url + ":" + accessToken)
      request.get(url, {
        auth: {
          bearer: accessToken
        }
      }, (error, response, body) => {
        log.info("Done request")
        if (error) {
          profile.hasAccess = false
          log.error("Whomp1", error)
        } else {
          log.info('Access validated')
          profile.hasAccess = JSON.parse(response.body).permissions.length > 0
        }
        return done(null, profile)
      })
    } else {
      log.info("Ping2")
      const url = 'https://www.googleapis.com/drive/v3/drives'
      request.get(url, {
        auth: {
          bearer: accessToken
        }
      }, (error, response, body) => {
        log.info("Done request 2")
        if (error) {
          profile.hasAccess = false
          log.error("Whomp2", error)
          return done(null, profile)
        } else {
          profile.hasAccess = JSON.parse(response.body).drives.filter((drive) => drive.id === process.env.DRIVE_ID).length > 0
          log.info('Access validated')
          return done(null, profile)
        }
      })
    }
  }))
}

const md5 = (data) => crypto.createHash('md5').update(data).digest('hex')

router.use(session({
  secret: process.env.SESSION_SECRET,
  resave: true,
  saveUninitialized: true
}))

router.use(passport.initialize())
router.use(passport.session())

// seralize/deseralization methods for extracting user information from the
// session cookie and adding it to the req.passport object
passport.serializeUser((user, done) => done(null, user))
passport.deserializeUser((obj, done) => done(null, obj))

const googleLoginOptions = {
  scope: [
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/drive.readonly'
  ],
  prompt: 'select_account'
}

router.get('/login', passport.authenticate(authStrategy, isSlackOauth ? {} : googleLoginOptions))

router.get('/logout', (req, res) => {
  req.logout()
  res.redirect('/')
})

router.get('/auth/redirect', passport.authenticate(authStrategy, {failureRedirect: '/login'}), (req, res) => {
  res.redirect(req.session.authRedirect || '/')
})

router.use((req, res, next) => {
  const isDev = process.env.NODE_ENV === 'development'
  const passportUser = (req.session.passport || {}).user || {}
  if (isDev || (req.isAuthenticated() && isAuthorized(passportUser))) {
    setUserInfo(req)
    return next()
  }

  if (req.isAuthenticated() && !isAuthorized(passportUser)) {
    log.info('Unauthorized!')
    return next(Error('Unauthorized'))
  }

  log.info('User not authenticated')
  req.session.authRedirect = req.path
  res.redirect('/login')
})

function isAuthorized(user) {
  const [{value: userEmail = ''} = {}] = user.emails || []
  const [userDomain] = userEmail.split('@').slice(-1)

  log.info('User Access:' + user.hasAccess)

  return user.hasAccess && (domains.has(userDomain) || domains.has(userEmail))
}

function setUserInfo(req) {
  if (process.env.NODE_ENV === 'development') {
    req.userInfo = {
      email: process.env.TEST_EMAIL || template('footer.defaultEmail'),
      userId: '10',
      analyticsUserId: md5('10library')
    }
    return
  }
  const email = isSlackOauth ? req.session.passport.user.email : req.session.passport.user.emails[0].value
  req.userInfo = req.userInfo ? req.userInfo : {
    userId: req.session.passport.user.id,
    analyticsUserId: md5(req.session.passport.user.id + 'library'),
    email
  }
}

module.exports = router
