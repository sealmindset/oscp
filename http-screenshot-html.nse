-- Copyright (C) 2012 Aaron Giuoco
-- http://giuoco.org
--
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation; version 2 dated June, 1991 or at your option
-- any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
-- GNU General Public License for more details.
--
-- A copy of the GNU General Public License is available in the source tree;
-- if not, write to the Free Software Foundation, Inc.,
-- 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

--@args path The path to request, such as <code>/index.php</code>. Default is <code>/</code>.
--@args useget Set to force GET requests instead of HEAD.
--@args outpath The path for all output (pictures, etc.).  Default is current directory.
--@args outfile The file name of the output file containing the HTML code.  Default is <code>screenshot.html</code>.
--@args imgquality Determines the quality of the images output by wkhtmltoimage. Default is 30.

description = [[
Version 1.3
September 4, 2014

Gets a screenshot from the host, header information from the host,
and outputs it to an HTML file.

This script contains the 2 NSE scripts http-headers by Ron Bowes and
http-screenshot by Ryan Linn.  I stitched them together and wrote the
output code to write all of the information to a file.

UPDATE 1.1
* Added pre and post actions so now a complete HTML file is written
* Changed format of HTML for better layout and organization

UPDATE 1.2
* Added option for image quality output using "imgquality" script arg.  Default is 30.
* Code modifications to make script compatible with NMAP 6.25 and Lua 5.2.

UPDATE 1.3
* Modified the check for HTTP status on port.  Now using "http.status ~= nil".
* Will not run the script on HTTP ports that respond with HTTP code 400, 501, or 503.  wkhtmltoimage seems hang when scanning ports with those response codes.
* Moved io.open() within PORTACTION closer to the first file write command.  This eliminates the "too many files open" error.
* Declared 'ret' variable within PORTACTION.  This error caused the script to fail and not write data to the HTML file.
* Added lots of debugging code for troubleshooting.
]]

author = "Aaron Giuoco (and thanks to Ryan Linn and Ron Bowes)"

license = "GPLv2"

categories = {"discovery", "safe"}

local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"


-- set global default vars
defaultoutfile = "screenshot.html"
defaultoutpath = ""
defaultquality = "30"

-- portrule = shortport.http

preaction = function()
	stdnse.print_debug(1, "Preaction function\n")
	local outpath = stdnse.get_script_args(SCRIPT_NAME..".outpath") or defaultoutpath
	local outfile = stdnse.get_script_args(SCRIPT_NAME..".outfile") or defaultoutfile
	local fh,err = io.open(outpath .. outfile,"w")
	stdnse.print_debug(1, "http-screenshot-html.nse: Opening File")
	-- Make sure file can be opened
    if err then return err end
	stdnse.print_debug(1, "http-screenshot-html.nse: File Opened")
    fh:write("<html>\n<head>\n<title>HTTP-ScreenShot-Outfile</title>\n</head>\n<body>\n\n")
    fh:close()
	stdnse.print_debug(1, "http-screenshot-html.nse: File Closed - PREaction")
end

portaction = function(host, port)
	-- Check to see if ssl is enabled, if it is, this will be set to "ssl"
    local ssl = port.version.service_tunnel
    -- The default URLs will start with http://
    local prefix = "http"
    -- Screenshots will be called <IP>:<port>.png
    local filename = host.ip .. "-" .. port.number .. ".png"
    local path = stdnse.get_script_args(SCRIPT_NAME..".path") or "/"
    local useget = stdnse.get_script_args(SCRIPT_NAME..".useget")
    local outpath = stdnse.get_script_args(SCRIPT_NAME..".outpath") or defaultoutpath
    local outfile = stdnse.get_script_args(SCRIPT_NAME..".outfile") or defaultoutfile
	local imgquality = stdnse.get_script_args(SCRIPT_NAME..".imgquality") or defaultquality
    local request_type = "HEAD"
    local status = false
    local http_result
    local k
    local v
	local ret

    -- Check if the user didn't want HEAD to be used
    if(useget == nil) then
        -- Try using HEAD first
        status, http_result = http.can_use_head(host, port, nil, path)
    end

    -- If head failed, try using GET
    if(status == false) then
        stdnse.print_debug(1, "http-screenshot-html.nse: HEAD request failed, falling back to GET")
        http_result = http.get(host, port, path)
        request_type = "GET"
    end

    -- If the page returns a proper HTTP header and HTTP status code, proceed with screenshot
	if ((http_result.status ~= nil) and (http_result.rawheader ~= nil) and (http_result.status ~= 501) and (http_result.status ~= 503) and (http_result.status ~= 400)) then
	
		table.insert(http_result.rawheader, "(Request type: " .. request_type .. ")")

	    -- If SSL is set on the port, switch the prefix to https
	    if(http_result.ssl == true) then
	        prefix = "https"
	    end

	    -- Execute the wkhtmltoimage command using host IP.
	    -- local cmd = "\"wkhtmltoimage-amd64\" -n " .. prefix .. "://" .. host.ip .. ":" .. port.number .. " " .. outpath .. filename
	    local cmd = "wkhtmltoimage --load-error-handling ignore --quality " .. imgquality .. " -n " .. prefix .. "://" .. host.ip .. ":" .. port.number .. " " .. outpath .. filename

	    stdnse.print_debug(1, "http-screenshot-html.nse: " .. cmd)
	    ret = os.execute(cmd)

	    -- If the host name is available, execute the wkhtmltoimage command using the host name.
	    if(host.name ~= "") then
	        -- cmd = "\"wkhtmltoimage-amd64\" -n " .. prefix .. "://" .. host.name .. ":" .. port.number .. " " .. outpath .. host.name .. "-" .. filename
	        cmd = "wkhtmltoimage --load-error-handling ignore --quality " .. imgquality .. " -n " .. prefix .. "://" .. host.name .. ":" .. port.number .. " " .. outpath .. host.name .. "-" .. filename
	        stdnse.print_debug(1, "http-screenshot-html.nse: " .. cmd)
	        ret = os.execute(cmd)
	    end
		
		stdnse.print_debug(1, "http-screenshot-html.nse: Image Creation Done")

	    -- If the command was successful, print the saved message, otherwise print the fail message
	    local cmd_result = "failed (verify wkhtmltoimage is in your path)"

	    if ret == true then
	        if(host.name ~= "") then
	            cmd_result = "Saved to " .. host.name .. "-" .. filename .. "\nSaved to " .. filename
	        else
	            cmd_result = "Saved to " .. filename
	        end
	    end
		
		-- Open File handle
		local fh,err = io.open(outpath .. outfile,"a")
		stdnse.print_debug(1, "http-screenshot-html.nse: Opening File")
		-- Make sure file can be opened
		if err then return err end
		stdnse.print_debug(1, "http-screenshot-html.nse: File Opened")
	
	    -- Open DIV tag
		stdnse.print_debug(1, "http-screenshot-html.nse: Writing DIV tags")
	    fh:write("\n<div style=\"border: 3px #7DA7FC solid;padding:10px;margin:10px;background-color:#E1E1E1\">\n")
	    -- Write H1 and H2 tags, open PRE tag, write HTTP Headers
		stdnse.print_debug(1, "http-screenshot-html.nse: Writing HEADER tags")
	    fh:write("<h1><u>" .. host.ip .. ":" .. port.number .. "</u></h1>\n")
	    fh:write(" <h2><u>HTTP Headers</u></h2>\n<pre>\n")
		stdnse.print_debug(1, "http-screenshot-html.nse: Writing RAW HTTP Header tags")
	    for k,v in pairs(http_result.rawheader)
	        do
	            fh:write(v .. "\n")
	    end
	    fh:write("</pre>\n")
	    -- Write HTML with link to page and screenshot image
		stdnse.print_debug(1, "http-screenshot-html.nse: Writing Screenshot Links")
	    fh:write("<h2><u>Screenshots</u></h2>\n")
	    fh:write("<p><a href=\"" .. prefix .. "://" .. host.ip .. ":" .. port.number .. "\" target=\"_blank\">" .. prefix .. "://" .. host.ip .. ":" .. port.number .. "</a></br>")
	    fh:write("<img src=\"" .. filename .. "\"></p>\n")
	    -- If host name is available, link to the host name and host name screenshot.
	    if(host.name ~= "") then
	        fh:write("<p><a href=\"" .. prefix .. "://" .. host.name .. ":" .. port.number .. "\" target=\"_blank\">" .. prefix .. "://" .. host.name .. ":" .. port.number .. "</a></br>")
	        fh:write("<img src=\"" .. host.name .. "-" .. filename .. "\"></p>\n")
	    end
	    -- Close DIV tag
		stdnse.print_debug(1, "http-screenshot-html.nse: Closing DIV tags")
	    fh:write("</div>\n")

	    -- Close the file
	    fh:close()
		stdnse.print_debug(1, "http-screenshot-html.nse: File Closed - PORTaction")

	    -- Return the output message
	    return stdnse.format_output(true, cmd_result)
	else
		if(http_result == nil) then
	        if(nmap.debugging() > 0) then
	            return "ERROR: Header request failed"
	        else
	            return nil
	        end
	    end

	    if(http_result.rawheader == nil) then
	        if(nmap.debugging() > 0) then
	            return "ERROR: Header request didn't return a proper header"
	        else
	            return nil
	        end
	    end
	end
end

postaction = function()
	stdnse.print_debug(1, "http-screenshot-html.nse: Postaction function")
	local outpath = stdnse.get_script_args(SCRIPT_NAME..".outpath") or defaultoutpath
	local outfile = stdnse.get_script_args(SCRIPT_NAME..".outfile") or defaultoutfile
	local fh,err = io.open(outpath .. outfile,"a")
	stdnse.print_debug(1, "http-screenshot-html.nse: Opening File")
	-- Make sure file can be opened
    if err then return err end
	stdnse.print_debug(1, "http-screenshot-html.nse: File Open")
    fh:write("</body>\n</html>")
    fh:close()
	stdnse.print_debug(1, "http-screenshot-html.nse: File Closed - POSTaction")
end

--- Function dispatch table
local actions = {
	prerule  = preaction,
	portrule = portaction,
	postrule = postaction
}

prerule = function() return true end
portrule = function() return true end
postrule = function() return true end

function action (...) return actions[SCRIPT_TYPE](...) end
