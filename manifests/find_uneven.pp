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
# \subsection{Uneven access permissions}
#
# \implements{unixsrg}{GEN001140}%
# \implements{macosxstig}{GEN001140 M6}%
# Check for system files and directories having ``uneven access permissions.''

class stig_misc::find_uneven {

    $system_dirs = "/etc /bin /usr/bin /sbin /usr/sbin"
       
    stig_misc::log_uneven { 'system_files_read':
        bit => '4',
        paths => $system_dirs,
    }
    stig_misc::log_uneven { 'system_files_write':
        bit => '2',
        paths => $system_dirs,
    }
    stig_misc::log_uneven { 'system_files_execute':
        bit => '1',
        paths => $system_dirs,
    }
}
