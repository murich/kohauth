<?php

defined('SYSPATH') or die('No direct script access.');

class Controller_Hauth extends Controller {

    function before()
    {
        parent::before();
        $config = Kohana::$config->load('hauth');
        $this->hybridauth = new Hybrid_Auth($config->get('hauth'));
    }

    public function action_endlogin()
    {
        $provider = $this->request->param('id');

        $adapter = $this->hybridauth->authenticate($provider);
        $user = (array) $adapter->getUserProfile();

        if (!empty($user)) {
            // store userdata to db if need
            $this->session = Session::instance();
            $this->session->bind('profile_url', $user['profileURL']);
        }

        $this->request->redirect('/');

    }

    public function action_startlogin()
    {
        $provider = $this->request->param('id');

        if (!empty($provider))
        {
            $adapter = $this->hybridauth->authenticate($provider, array("hauth_return_to'=>'/hauth/endlogin/$provider?forward=".@$_GET['forward']));
            $this->request->redirect("/hauth/endlogin/$provider?forward=".@$_GET['forward']);
        } else
        {
            Hybrid_Endpoint::process();
        }
    }

    public function action_getprofile()
    {
        $this->auto_render = false;
        $provider = $this->request->param('id');
        
        if (!empty($provider))
        {
            $adapter = $this->hybridauth->authenticate($provider);
            $user_profile = (array) $adapter->getUserProfile();
        } else
        {
            $user_profile = array();
        }
        
        
        $this->response->body(json_encode($user_profile));
        
        
    }

    public function action_call_adapter_procedure(){
        if(!$this->request->is_initial()){ // only for internal requests
            $this->auto_render = false;
            $adapter_name = $this->request->param('id');
            $adapter_procedure = $this->request->param('sub_id');
            $this->hybridauth->restoreSessionData('a:3:{s:40:"hauth_session.twitter.token.access_token";s:58:"s:50:"!!!access_token";";s:47:"hauth_session.twitter.token.access_token_secret";s:48:"s:40:"!!!access_token_secret";";s:34:"hauth_session.twitter.is_logged_in";s:4:"i:1;";}');
            $adapter = $this->hybridauth->authenticate($adapter_name);

            $result = (array)  call_user_func_array(array($adapter, $adapter_procedure), $this->request->query());

            $this->response->body(json_encode($result));
        }
        else throw new HTTP_Exception_403;
    }

}