rule leverage_a
{
	meta:
		author = "earada@alienvault.com"
		version = "1.0"
		description = "OSX/Leverage.A"
		date = "2013/09"
	strings:
		$a1 = "ioreg -l | grep \"IOPlatformSerialNumber\" | awk -F"
		$a2 = "+:Users:Shared:UserEvent.app:Contents:MacOS:"
		$a3 = "rm '/Users/Shared/UserEvent.app/Contents/Resources/UserEvent.icns'"
		$script1 = "osascript -e 'tell application \"System Events\" to get the hidden of every login item'"
		$script2 = "osascript -e 'tell application \"System Events\" to get the name of every login item'"
		$script3 = "osascript -e 'tell application \"System Events\" to get the path of every login item'"
		$properties = "serverVisible \x00"
	condition:
		all of them
}