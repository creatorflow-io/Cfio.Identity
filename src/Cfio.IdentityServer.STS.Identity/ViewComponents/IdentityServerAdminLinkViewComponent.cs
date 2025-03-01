﻿// Copyright (c) Jan Škoruba. All Rights Reserved.
// Licensed under the Apache License, Version 2.0.

using Microsoft.AspNetCore.Mvc;
using Cfio.IdentityServer.STS.Identity.Configuration.Interfaces;

namespace Cfio.IdentityServer.STS.Identity.ViewComponents
{
    public class IdentityServerAdminLinkViewComponent : ViewComponent
    {
        private readonly IRootConfiguration _configuration;

        public IdentityServerAdminLinkViewComponent(IRootConfiguration configuration)
        {
            _configuration = configuration;
        }

        public IViewComponentResult Invoke()
        {
            var identityAdminUrl = _configuration.AdminConfiguration.IdentityAdminBaseUrl;

            return View(model: identityAdminUrl);
        }
    }
}







