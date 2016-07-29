# Bitbucket OAuth2 Provider for Laravel Socialite

[![Latest Stable Version](https://poser.pugx.org/akkyoh/socialite_bitbucket/v/stable.svg)](https://packagist.org/packages/akkyoh/socialite_bitbucket)
[![Total Downloads](https://poser.pugx.org/akkyoh/socialite_bitbucket/downloads.svg)](https://packagist.org/packages/akkyoh/socialite_bitbucket)
[![Latest Unstable Version](https://poser.pugx.org/akkyoh/socialite_bitbucket/v/unstable.svg)](https://packagist.org/packages/akkyoh/socialite_bitbucket)

## Install

**1. COMPOSER**
```
composer require akkyoh/socialite_bitbucket
```

**2. SERVICE PROVIDER**
- Remove Laravel\Socialite\SocialiteServiceProvider from your providers[] array in config\app.php if you have added it already.
- Add \SocialiteProviders\Manager\ServiceProvider::class to your providers[] array in config\app.php.
```
// For example
'providers' => [
    // a whole bunch of providers
    // remove 'Laravel\Socialite\SocialiteServiceProvider',
    \SocialiteProviders\Manager\ServiceProvider::class, // add
];
```
- If you would like to use the Socialite Facade, you need to [install it](https://laravel.com/docs/5.0/authentication#social-authentication).

**3. ADD THE EVENT AND LISTENERS**
- Add SocialiteProviders\Manager\SocialiteWasCalled event to your listen[] array in <app_name>/Providers/EventServiceProvider.
- Add your listeners (i.e. the ones from the providers) to the SocialiteProviders\Manager\SocialiteWasCalled[] that you just created.
- The listener that you add for this provider is 'Akkyoh\SocialiteBitbucket\BitbucketExtendSocialite@handle',.
- Note: You do not need to add anything for the built-in socialite providers unless you override them with your own providers.
```
// For example
protected $listen = [
    \SocialiteProviders\Manager\SocialiteWasCalled::class => [
        // add your listeners (aka providers) here
        'Akkyoh\SocialiteBitbucket\BitbucketExtendSocialite@handle',
    ],
];
```

**4. ENVIRONMENT VARIABLES**

If you add environment values to your .env as exactly shown below, **you do not need to add an entry to the services array**.

###### APPEND PROVIDER VALUES TO YOUR .ENV FILE

```
// other values above
BITBUCKET_KEY=yourkeyfortheservice
BITBUCKET_SECRET=yoursecretfortheservice
BITBUCKET_REDIRECT_URI=https://example.com/login
```

###### ADD TO CONFIG/SERVICES.PHP.

You do not need to add this if you add the values to the .env exactly as shown above. The values below are provided as a convenience in the case that a developer is not able to use the .env method

```
'bitbucket' => [
    'client_id' => env('BITBUCKET_KEY'),
    'client_secret' => env('BITBUCKET_SECRET'),
    'redirect' => env('BITBUCKET_REDIRECT_URI'),
],
```

# USAGE

You should now be able to use it like you would regularly use Socialite (assuming you have the facade installed):

```
return Socialite::driver('bitbucket') -> redirect();
```

# RESOURCES

[Socialite Providers](http://socialiteproviders.github.io/)
[Laravel Socialite Docs](https://github.com/laravel/socialite)