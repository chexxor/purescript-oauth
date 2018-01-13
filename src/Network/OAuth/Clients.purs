module Network.OAuth.Clients where


-- Example AuthEndpointClient implementation/runtime.

authEndpointClientForCLIApp ::
  forall eff requestType.
  AuthEndpointClient requestType
authEndpointClientForCLIApp =
  AuthEndpointClient spawnBrowser listenForAuth
  where
    spawnBrowser :: AuthRequestArgs requestType -> Eff (cp :: CHILD_PROCESS | eff) ChildProcess
    spawnBrowser authRequest =
        ChildProcess.spawn (fst openCmd)
          (snd openCmd <> print <<< authReqAsQuery authReq)
          defaultSpawnOptions
        where
          authReqAsQuery :: AuthRequestArgs requestType -> Query
          authReqAsQuery (AuthRequestArgs client_id
            redirect_uri scope state) = Query
              Cons (Tuple "request_type" $ Just "code") -- !!! token?
                $ Cons (Tuple "client_id" $ Just client_id)
                $ Cons (Tuple "redirect_uri" $ Just redirect_uri)
                $ Nil
                <> (maybe mempty (\scope' -> Tuple "scope" $ Just scope') scope)
                <> (maybe mempty (\state' -> Tuple "state" $ Just state') state)
          openCmd = Desktops.browserOpenCmdForDesktop
              $ mostCommonDesktopForPlatform $ fromMaybe Linux platform
    listenForAuth ::
      (Either AuthorizationEndpointErrorResponse (AuthorizationEndpointSuccessResponse tokenType)
        -> Eff eff Unit
      )
      -> Eff eff Unit
    listenForAuth cb = do
      server <- createServer $ listenHandler cb
      !!! Move to util, consider using lens instead.
      let portFromUri (URI _ (HierarchicalPart maybeAuthority) _) _ _) =
            maybeAuthority >>= firstPortFromAuthority
              where
                portFromPair (Tuple _ maybePort) = maybePort
                firstPortFromAuthority (Authority _ hostPorts) =
                  head hostPorts >>= portFromPair
      -- !!! Clean up server when done.
      listen server
          { hostname: "localhost"
          , port: portFromUri redirect_uri
          , backlog: Nothing
          } $ void do
        log "Listening on port 8080 at " <> print redirect_uri
          <> " for Authorization Token."
      where
        listenHandler cb' req res = do
          -- log (requestMethod req <> " " <> requestURL req)
          let outputStream = responseAsStream res
          let parsedUri = parse $ requestURL req
          case requestMethod req, parsedUri of
            "GET" url, Right uri@(URI _ h (Just query) _) -> do
               when $ 0 == indexOf (print redirect_uri) (print h)
               let authRes = authResponseFromQuery query
               _ <- cb' $ Right authRes
               setStatusCode res 200
               end outputStream (pure unit)
            -- !!! Better error messages
            _, _ -> unsafeCrashWith "Failed to receive authorization token."
               setStatusCode res 400
               end outputStream (pure unit)
        authResponseFromQuery :: Query -> Either String (AuthorizationEndpointSuccessResponse tokenType)
        authResponseFromQuery (Query kvs) =
          (find "code" kvs # note "No authorization code in response")
          >>= parseAuthTokenRequestCode
          <$>
          (\code ->
            AuthorizationEndpointSuccessResponse $ Tuple code (find "state" kvs)
          )

