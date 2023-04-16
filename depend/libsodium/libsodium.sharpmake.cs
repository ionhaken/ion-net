using Sharpmake;

using System;
using System.Collections.Generic;
	
[module: Sharpmake.Include("../../../CoreLib/Common.sharpmake.cs")]

namespace ion
{	
	[Sharpmake.Generate]
    public class libsodiumProject : ExternalLibProject
    {
        public libsodiumProject()
        {
            Name = "libsodium";
            SourceRootPath = @"[project.SharpmakeCsPath]\src\libsodium";
            AddTargets(Settings.GetTargets());
        }

        [Configure()]
        public void ConfigureAll(Configuration conf, Target target)
        {		
			conf.IncludePaths.Add(@"[project.RootPath]\include\sodium");				
        }
    }
}