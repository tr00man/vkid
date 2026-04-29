<?php

namespace tr00man\VKID;

use SocialiteProviders\Manager\SocialiteWasCalled;

final class VKIDExtendSocialite
{
    public function handle(SocialiteWasCalled $event): void
    {
        $event->extendSocialite('vkontakte', Provider::class);
    }
}
