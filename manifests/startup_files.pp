# % CMITS - Configuration Management for Information Technology Systems
# % Based on <https://github.com/afseo/cmits>.
# % Copyright 2015 Jared Jennings <mailto:jjennings@fastmail.fm>.
# %
# % Licensed under the Apache License, Version 2.0 (the "License");
# % you may not use this file except in compliance with the License.
# % You may obtain a copy of the License at
# %
# %    http://www.apache.org/licenses/LICENSE-2.0
# %
# % Unless required by applicable law or agreed to in writing, software
# % distributed under the License is distributed on an "AS IS" BASIS,
# % WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# % See the License for the specific language governing permissions and
# % limitations under the License.
# \subsection{Startup file permissions}

class stig_misc::startup_files {
    case $osfamily {
# The Mac OS X STIG check content and fix text fails to delineate ``system
# start-up files'' any more specifically than ``every file on the root
# volume.''
        'Darwin': { include stig_misc::vendor_permissions }
# The RHEL 5 STIG check content and fix text defines ``system start-up files''
# to be the same set of files as ``run control scripts.''
        'RedHat': { include stig_misc::run_control_scripts }
        default:  { fail "unimplemented on ${::osfamily}" }
    }
}
