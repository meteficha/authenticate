{-# LANGUAGE CPP, DeriveDataTypeable, FlexibleContexts, MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings, StandaloneDeriving, BangPatterns              #-}
module Web.Authenticate.OAuth
    ( -- * Data types
      OAuth, def, newOAuth, oauthServerName, oauthRequestUri, oauthAccessTokenUri,
      oauthAuthorizeUri, oauthSignatureMethod, oauthConsumerKey,
      oauthConsumerSecret, oauthCallback, oauthRealm, oauthVersion,
      OAuthVersion(..), SignMethod(..), Credential(..), OAuthException(..),
      -- * Operations for credentials
      newCredential, emptyCredential, insert, delete, inserts, injectVerifier,
      -- * Signature
      signOAuth, genSign,
      -- * Url & operation for authentication
      -- ** Temporary credentials
      getTemporaryCredential, getTemporaryCredentialWithScope,
      getTemporaryCredentialProxy, getTemporaryCredential',
      -- ** Authorization URL
      authorizeUrl, authorizeUrl',
      -- ** Finishing authentication
      getAccessToken,
      getAccessTokenProxy,
      getAccessToken',
      -- * Utility Methods
      paramEncode, addScope, addMaybeProxy
    ) where

import           Blaze.ByteString.Builder     (toByteString)
import           Control.Exception
import           Control.Monad
import           Control.Monad.IO.Class       (MonadIO, liftIO)
import qualified Crypto.Random                as R
import           Crypto.Types.PubKey.RSA      (PrivateKey (..))
import           Data.ByteString.Base64       as B64
import           Data.ByteString.Base64.URL   as B64URL
import qualified Data.ByteString.Char8        as BS
import qualified Data.ByteString.Lazy.Char8   as BSL
import           Data.Char
import           Data.Default
import           Data.Digest.Pure.SHA
import qualified Data.IORef                   as I
import           Data.List                    (sort)
import           Data.Maybe
import           Data.Time
import           Data.Tuple                   (swap)
import           Network.HTTP.Client
import           Network.HTTP.Types           ( Header, SimpleQuery, parseSimpleQuery
                                              , renderSimpleQuery, status200, urlEncode )
#if MIN_VERSION_base(4,7,0)
import Data.Data hiding (Proxy (..))
#else
import Data.Data
#endif
import Codec.Crypto.RSA (rsassa_pkcs1_v1_5_sign, hashSHA1)


----------------------------------------------------------------------
-- Data types


-- | Data type for OAuth client (consumer).
--
-- The constructor for this data type is not exposed.
-- Instead, you should use the 'def' method or 'newOAuth' function to retrieve a default instance,
-- and then use the records below to make modifications.
-- This approach allows us to add configuration options without breaking backwards compatibility.
data OAuth = OAuth { oauthServerName      :: String -- ^ Service name (default: @\"\"@)
                   , oauthRequestUri      :: String
                   -- ^ URI to request temporary credential (default: @\"\"@).
                   --   You MUST specify if you use 'getTemporaryCredential'', 'getTemporaryCredentialProxy'
                   --   or 'getTemporaryCredential'; otherwise you can just leave this empty.
                   , oauthAccessTokenUri  :: String
                   -- ^ Uri to obtain access token (default: @\"\"@).
                   --   You MUST specify if you use 'getAcessToken' or 'getAccessToken'';
                   --   otherwise you can just leave this empty.
                   , oauthAuthorizeUri    :: String
                   -- ^ Uri to authorize (default: @\"\"@).
                   --   You MUST specify if you use 'authorizeUrl' or 'authorizeZUrl'';
                   --   otherwise you can just leave this empty.
                   , oauthSignatureMethod :: SignMethod
                   -- ^ Signature Method (default: 'HMACSHA1')
                   , oauthConsumerKey     :: BS.ByteString
                   -- ^ Consumer key (You MUST specify)
                   , oauthConsumerSecret  :: BS.ByteString
                   -- ^ Consumer Secret (You MUST specify)
                   , oauthCallback        :: Maybe BS.ByteString
                   -- ^ Callback uri to redirect after authentication (default: @Nothing@)
                   , oauthRealm           :: Maybe BS.ByteString
                   -- ^ Optional authorization realm (default: @Nothing@)
                   , oauthVersion         :: OAuthVersion
                   -- ^ OAuth spec version (default: 'OAuth10a')
                   } deriving (Show, Eq, Read, Data, Typeable)


data OAuthVersion = OAuth10     -- ^ OAuth protocol ver 1.0 (no oauth_verifier; differs from RFC 5849).
                  | OAuth10a    -- ^ OAuth protocol ver 1.0a. This corresponds to community's 1.0a spec and RFC 5849.
                    deriving (Show, Eq, Enum, Ord, Data, Typeable, Read)


-- | Default value for OAuth datatype.
-- You must specify at least oauthServerName, URIs and Tokens.
newOAuth :: OAuth
newOAuth = OAuth { oauthSignatureMethod = HMACSHA1
                 , oauthCallback = Nothing
                 , oauthRealm    = Nothing
                 , oauthServerName = ""
                 , oauthRequestUri = ""
                 , oauthAccessTokenUri = ""
                 , oauthAuthorizeUri = ""
                 , oauthConsumerKey = error "You MUST specify oauthConsumerKey parameter."
                 , oauthConsumerSecret = error "You MUST specify oauthConsumerSecret parameter."
                 , oauthVersion = OAuth10a
                 }

instance Default OAuth where
  def = newOAuth


-- | Data type for signature method.
data SignMethod = PLAINTEXT
                | HMACSHA1
                | RSASHA1 PrivateKey
                  deriving (Show, Eq, Read, Data, Typeable)


data OAuthException = OAuthException String
                      deriving (Show, Eq, Data, Typeable)

instance Exception OAuthException


----------------------------------------------------------------------
-- Credentials


-- | Data type for redential.
data Credential = Credential { unCredential :: [(BS.ByteString, BS.ByteString)] }
                  deriving (Show, Eq, Ord, Read, Data, Typeable)


-- | Convenient function to create 'Credential' with OAuth Token and Token Secret.
newCredential :: BS.ByteString -- ^ value for oauth_token
              -> BS.ByteString -- ^ value for oauth_token_secret
              -> Credential
newCredential tok sec = Credential [("oauth_token", tok), ("oauth_token_secret", sec)]


-- | Empty credential.
emptyCredential :: Credential
emptyCredential = Credential []


-- | Insert an oauth parameter into given 'Credential'.
insert :: BS.ByteString -- ^ Parameter Name
       -> BS.ByteString -- ^ Value
       -> Credential    -- ^ Credential
       -> Credential    -- ^ Result
insert k v = Credential . insertMap k v . unCredential


-- | Convenient method for inserting multiple parameters into credential.
inserts :: [(BS.ByteString, BS.ByteString)] -> Credential -> Credential
inserts = flip $ foldr (uncurry insert)


-- | Remove an oauth parameter for key from given 'Credential'.
delete :: BS.ByteString -- ^ Parameter name
       -> Credential    -- ^ Credential
       -> Credential    -- ^ Result
delete key = Credential . deleteMap key . unCredential


-- | Insert @oauth-verifier@ on a 'Credential'.
injectVerifier :: BS.ByteString -> Credential -> Credential
injectVerifier = insert "oauth_verifier"


----------------------------------------------------------------------
-- Signature

-- | Add OAuth headers & sign to 'Request'.
--
--  For the random number generator, we recommend using the
--  @cprng-aes@ package.
signOAuth :: (MonadIO m, R.CPRG gen)
          => OAuth              -- ^ OAuth Application
          -> I.IORef gen        -- ^ CPRNG (cf. @cprng-aes@)
          -> Credential         -- ^ Credential
          -> Request            -- ^ Original Request
          -> m Request          -- ^ Signed OAuth Request
signOAuth oa genVar crd req = do
  crd' <- addTimeStamp =<< addNonce genVar crd
  let tok = injectOAuthToCred oa crd'
  sign <- genSign oa tok req
  return $ addAuthHeader prefix (insert "oauth_signature" sign tok) req
  where
    prefix = case oauthRealm oa of
      Nothing -> "OAuth "
      Just v  -> "OAuth realm=\"" `BS.append` v `BS.append` "\","


-- | Generate OAuth signature.  Used by 'signOAuth'.
genSign :: MonadIO m => OAuth -> Credential -> Request -> m BS.ByteString
genSign oa tok req =
  case oauthSignatureMethod oa of
    HMACSHA1 -> do
      text <- getBaseString tok req
      let key  = BS.intercalate "&" $ map paramEncode [oauthConsumerSecret oa, tokenSecret tok]
      return $ B64.encode $ BSL.toStrict $ bytestringDigest $ hmacSha1 (BSL.fromStrict key) text
    PLAINTEXT ->
      return $ BS.intercalate "&" $ map paramEncode [oauthConsumerSecret oa, tokenSecret tok]
    RSASHA1 pr ->
      liftM (B64.encode . BSL.toStrict . rsassa_pkcs1_v1_5_sign hashSHA1 pr) (getBaseString tok req)


----------------------------------------------------------------------
-- Temporary credentails


-- | Get temporary credential for requesting acces token.
getTemporaryCredential :: (MonadIO m, R.CPRG gen)
                       => OAuth         -- ^ OAuth Application
                       -> I.IORef gen   -- ^ CPRNG (cf. @cprng-aes@)
                       -> Manager
                       -> m Credential -- ^ Temporary Credential (Request Token & Secret).
getTemporaryCredential = getTemporaryCredential' id


-- | Get temporary credential for requesting access token with Scope parameter.
getTemporaryCredentialWithScope :: (MonadIO m, R.CPRG gen)
                                => BS.ByteString -- ^ Scope parameter string
                                -> OAuth         -- ^ OAuth Application
                                -> I.IORef gen   -- ^ CPRNG (cf. @cprng-aes@)
                                -> Manager
                                -> m Credential -- ^ Temporay Credential (Request Token & Secret).
getTemporaryCredentialWithScope = getTemporaryCredential' . addScope


-- | Get temporary credential for requesting access token via the proxy.
getTemporaryCredentialProxy :: (MonadIO m, R.CPRG gen)
                            => Maybe Proxy   -- ^ Proxy
                            -> OAuth         -- ^ OAuth Application
                            -> I.IORef gen   -- ^ CPRNG (cf. @cprng-aes@)
                            -> Manager
                            -> m Credential -- ^ Temporary Credential (Request Token & Secret).
getTemporaryCredentialProxy = getTemporaryCredential' . addMaybeProxy


getTemporaryCredential' :: (MonadIO m, R.CPRG gen)
                        => (Request -> Request)       -- ^ Request Hook
                        -> OAuth                      -- ^ OAuth Application
                        -> I.IORef gen                -- ^ CPRNG (cf. @cprng-aes@)
                        -> Manager
                        -> m Credential    -- ^ Temporary Credential (Request Token & Secret).
getTemporaryCredential' hook oa genVar manager = do
  let req = fromJust $ parseUrl $ oauthRequestUri oa
      crd = maybe id (insert "oauth_callback") (oauthCallback oa) $ emptyCredential
  req' <- signOAuth oa genVar crd $ hook (req { method = "POST" })
  rsp <- liftIO $ httpLbs req' manager
  if responseStatus rsp == status200
    then do
      let dic = parseSimpleQuery . BSL.toStrict . responseBody $ rsp
      return $ Credential dic
    else liftIO . throwIO . OAuthException $ "Gaining OAuth Temporary Credential Failed: " ++ BSL.unpack (responseBody rsp)


----------------------------------------------------------------------
-- Authorization URL


-- | URL to obtain OAuth verifier.
authorizeUrl :: OAuth           -- ^ OAuth Application
             -> Credential      -- ^ Temporary Credential (Request Token & Secret)
             -> String          -- ^ URL to authorize
authorizeUrl = authorizeUrl' $ \oa -> const [("oauth_consumer_key", oauthConsumerKey oa)]


-- | Convert OAuth and Credential to URL to authorize.
--   This takes function to choice parameter to pass to the server other than
--   /oauth_callback/ or /oauth_token/.
authorizeUrl' :: (OAuth -> Credential -> SimpleQuery)
              -> OAuth           -- ^ OAuth Application
              -> Credential      -- ^ Temporary Credential (Request Token & Secret)
              -> String          -- ^ URL to authorize
authorizeUrl' f oa cr = oauthAuthorizeUri oa ++ BS.unpack (renderSimpleQuery True queries)
  where fixed   = ("oauth_token", token cr):f oa cr
        queries =
          case oauthCallback oa of
            Nothing       -> fixed
            Just callback -> ("oauth_callback", callback):fixed


----------------------------------------------------------------------
-- Finishing authentication


-- | Get Access token.
getAccessToken
               :: (MonadIO m, R.CPRG gen)
               => OAuth         -- ^ OAuth Application
               -> I.IORef gen   -- ^ CPRNG (cf. @cprng-aes@)
               -> Credential    -- ^ Temporary Credential (with oauth_verifier if >= 1.0a)
               -> Manager
               -> m Credential -- ^ Token Credential (Access Token & Secret)
getAccessToken = getAccessToken' id


-- | Get Access token via the proxy.
getAccessTokenProxy
               :: (MonadIO m, R.CPRG gen)
               => Maybe Proxy   -- ^ Proxy
               -> OAuth         -- ^ OAuth Application
               -> I.IORef gen   -- ^ CPRNG (cf. @cprng-aes@)
               -> Credential    -- ^ Temporary Credential (with oauth_verifier if >= 1.0a)
               -> Manager
               -> m Credential -- ^ Token Credential (Access Token & Secret)
getAccessTokenProxy = getAccessToken' . addMaybeProxy


getAccessToken' :: (MonadIO m, R.CPRG gen)
                => (Request -> Request)       -- ^ Request Hook
                -> OAuth                      -- ^ OAuth Application
                -> I.IORef gen                -- ^ CPRNG (cf. @cprng-aes@)
                -> Credential                 -- ^ Temporary Credential (with oauth_verifier if >= 1.0a)
                -> Manager
                -> m Credential     -- ^ Token Credential (Access Token & Secret)
getAccessToken' hook oa genVar cr manager = do
  let req = hook (fromJust $ parseUrl $ oauthAccessTokenUri oa) { method = "POST" }
  rsp <- liftIO $ flip httpLbs manager =<< signOAuth oa genVar (if oauthVersion oa == OAuth10 then delete "oauth_verifier" cr else cr) req
  if responseStatus rsp == status200
    then do
      let dic = parseSimpleQuery . BSL.toStrict . responseBody $ rsp
      return $ Credential dic
    else liftIO . throwIO . OAuthException $ "Gaining OAuth Token Credential Failed: " ++ BSL.unpack (responseBody rsp)


baseTime :: UTCTime
baseTime = UTCTime day 0
  where
    day = ModifiedJulianDay 40587


showSigMtd :: SignMethod -> BS.ByteString
showSigMtd PLAINTEXT = "PLAINTEXT"
showSigMtd HMACSHA1  = "HMAC-SHA1"
showSigMtd (RSASHA1 _) = "RSA-SHA1"


addNonce :: (MonadIO m, R.CPRG gen) => I.IORef gen -> Credential -> m Credential
addNonce genVar cred = do
  -- We want at least 128 bits of entropy.  Since both 16 and 18
  -- bytes of input will generate 24 bytes of base64url output,
  -- we use 144 bits.
  randomBytes <- liftIO $ I.atomicModifyIORef genVar $ swap . R.cprgGenerate 18
  let !nonce = B64URL.encode randomBytes
  return $ insert "oauth_nonce" nonce cred


addTimeStamp :: MonadIO m => Credential -> m Credential
addTimeStamp cred = do
  stamp <- (floor . (`diffUTCTime` baseTime)) `liftM` liftIO getCurrentTime
  return $ insert "oauth_timestamp" (BS.pack $ show (stamp :: Integer)) cred


injectOAuthToCred :: OAuth -> Credential -> Credential
injectOAuthToCred oa cred =
    inserts [ ("oauth_signature_method", showSigMtd $ oauthSignatureMethod oa)
            , ("oauth_consumer_key", oauthConsumerKey oa)
            , ("oauth_version", "1.0")
            ] cred


addAuthHeader :: BS.ByteString -> Credential -> Request -> Request
addAuthHeader prefix (Credential cred) req =
  req { requestHeaders = insertMap "Authorization" (renderAuthHeader prefix cred) $ requestHeaders req }


renderAuthHeader :: BS.ByteString -> [(BS.ByteString, BS.ByteString)] -> BS.ByteString
renderAuthHeader prefix = (prefix `BS.append`). BS.intercalate "," . map (\(a,b) -> BS.concat [paramEncode a, "=\"",  paramEncode b, "\""]) . filter ((`elem` ["oauth_token", "oauth_verifier", "oauth_consumer_key", "oauth_signature_method", "oauth_timestamp", "oauth_nonce", "oauth_version", "oauth_callback", "oauth_signature"]) . fst)


getBaseString :: MonadIO m => Credential -> Request -> m BSL.ByteString
getBaseString tok req = do
  let bsMtd  = BS.map toUpper $ method req
      isHttps = secure req
      scheme = if isHttps then "https" else "http"
      bsPort = if (isHttps && port req /= 443) || (not isHttps && port req /= 80)
                 then ':' `BS.cons` BS.pack (show $ port req) else ""
      bsURI = BS.concat [scheme, "://", host req, bsPort, path req]
      bsQuery = parseSimpleQuery $ queryString req
  bsBodyQ <- if isBodyFormEncoded $ requestHeaders req
                  then liftM parseSimpleQuery $ toBS (requestBody req)
                  else return []
  let bsAuthParams = filter ((`elem`["oauth_consumer_key","oauth_token", "oauth_version","oauth_signature_method","oauth_timestamp", "oauth_nonce", "oauth_verifier", "oauth_version","oauth_callback"]).fst) $ unCredential tok
      allParams = bsQuery++bsBodyQ++bsAuthParams
      bsParams = BS.intercalate "&" $ map (\(a,b)->BS.concat[a,"=",b]) $ sort
                   $ map (\(a,b) -> (paramEncode a,paramEncode b)) allParams
  -- parameter encoding method in OAuth is slight different from ordinary one.
  -- So this is OK.
  return $ BSL.intercalate "&" $ map (BSL.fromStrict . paramEncode) [bsMtd, bsURI, bsParams]


----------------------------------------------------------------------
-- Utilities


-- | Encode a string using the percent encoding method for OAuth.
paramEncode :: BS.ByteString -> BS.ByteString
paramEncode = urlEncode True


addScope :: BS.ByteString -> Request -> Request
addScope scope req | BS.null scope = req
                   | otherwise     = urlEncodedBody [("scope", scope)] req


token, tokenSecret :: Credential -> BS.ByteString
token = fromMaybe "" . lookup "oauth_token" . unCredential
tokenSecret = fromMaybe "" . lookup "oauth_token_secret" . unCredential


addMaybeProxy :: Maybe Proxy -> Request -> Request
addMaybeProxy p req = req { proxy = p }


insertMap :: Eq a => a -> b -> [(a,b)] -> [(a,b)]
insertMap key val = ((key,val):) . filter ((/=key).fst)

deleteMap :: Eq a => a -> [(a,b)] -> [(a,b)]
deleteMap k = filter ((/=k).fst)


toBS :: MonadIO m => RequestBody -> m BS.ByteString
toBS (RequestBodyLBS l) = return $ BSL.toStrict l
toBS (RequestBodyBS s) = return s
toBS (RequestBodyBuilder _ b) = return $ toByteString b
toBS (RequestBodyStream _ givesPopper) = toBS' givesPopper
toBS (RequestBodyStreamChunked givesPopper) = toBS' givesPopper

toBS' :: MonadIO m => GivesPopper () -> m BS.ByteString
toBS' gp = liftIO $ do
    ref <- I.newIORef BS.empty
    gp (go ref)
    I.readIORef ref
  where
    go ref popper =
        loop id
      where
        loop front = do
            bs <- popper
            if BS.null bs
                then I.writeIORef ref $ BS.concat $ front []
                else loop (front . (bs:))


isBodyFormEncoded :: [Header] -> Bool
isBodyFormEncoded = maybe False (=="application/x-www-form-urlencoded") . lookup "Content-Type"
