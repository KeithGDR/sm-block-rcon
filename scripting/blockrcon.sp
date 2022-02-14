#pragma semicolon 1
#pragma newdecls required

#define PLUGIN_VERSION "1.0.1"
#define PLUGIN_DESCRIPTION "Disables all access to RCON-based commands."

#include <sourcemod>
#include <smrcon>

ConVar convar_Status;
ConVar convar_LogAttempts;
ConVar convar_LogFormat;
ConVar convar_Password;

ArrayList g_Whitelisted;

public Plugin myinfo = 
{
	name = "Block RCON", 
	author = "Drixevel", 
	description = PLUGIN_DESCRIPTION, 
	version = PLUGIN_VERSION, 
	url = "https://drixevel.dev/"
};

public void OnPluginStart()
{	
	CreateConVar("sm_blockrcon_version", PLUGIN_VERSION, PLUGIN_DESCRIPTION, FCVAR_REPLICATED | FCVAR_NOTIFY | FCVAR_SPONLY | FCVAR_DONTRECORD);
	convar_Status = CreateConVar("sm_blockrcon_status", "1", "Status of the plugin.", FCVAR_NOTIFY, true, 0.0, true, 1.0);
	convar_LogAttempts = CreateConVar("sm_blockrcon_logattempts", "1", "Log any attempts used to access the RCON command.", FCVAR_NOTIFY, true, 0.0, true, 1.0);
	convar_LogFormat = CreateConVar("sm_blockrcon_logformat", ".%m_%y", "Log formatting to use for the postfix information. (Can be empty)", FCVAR_NOTIFY, true);

	AutoExecConfig();
	
	convar_Password = FindConVar("rcon_password");
	convar_Password.AddChangeHook(HookConVar_Password);
	
	g_Whitelisted = new ArrayList(ByteCountToCells(64));
	ParseWhitelisted();
}

void ParseWhitelisted()
{
	char sPath[PLATFORM_MAX_PATH];
	BuildPath(Path_SM, sPath, sizeof(sPath), "configs/rcon.whitelisted.cfg");
	
	File file = OpenFile(sPath, "r");
	
	if (file == null)
		ThrowError("Error while parsing config: %s", sPath);
	
	g_Whitelisted.Clear();
	
	char sLine[64];
	while (file.EndOfFile() && file.ReadLine(sLine, sizeof(sLine)))
	{
		TrimString(sLine);
		g_Whitelisted.PushString(sLine);
	}
	
	file.Close();
	LogMessage("%i IP addresses whitelisted for RCON use.", g_Whitelisted.Length);
}

public void OnConfigsExecuted()
{
	//Set the password to empty since that disables it.
	convar_Password.SetString("");
}

public Action SMRCon_OnAuth(int rconId, const char[] address, const char[] password, bool &allow)
{
	if (convar_Status.BoolValue && g_Whitelisted.FindString(address) == -1)
	{
		allow = false;
		RCONLog("RCON command attempt: %s - %s", strlen(address) > 0 ? address : "N/A", strlen(password) > 0 ? password : "N/A");
		return Plugin_Changed;
	}
	
	return Plugin_Continue;
}

public void HookConVar_Password(ConVar convar, const char[] oldValue, const char[] newValue)
{
	if (convar_Status.BoolValue && strlen(newValue) > 0)
	{
		RCONLog("RCON password change attempt: %s - %s", strlen(oldValue) > 0 ? oldValue : "N/A", strlen(newValue) > 0 ? newValue : "N/A");
		convar.SetString(oldValue);
	}
}

void RCONLog(const char[] sFormat, any ...)
{
	if (!convar_LogAttempts.BoolValue)
		return;
	
	char sBuffer[1024];
	VFormat(sBuffer, sizeof(sBuffer), sFormat, 2);
	
	char sTimeFormat[32];
	convar_LogFormat.GetString(sTimeFormat, sizeof(sTimeFormat));
	
	char sTime[32];
	FormatTime(sTime, sizeof(sTime), sTimeFormat);
	
	char sLogPath[PLATFORM_MAX_PATH];
	BuildPath(Path_SM, sLogPath, sizeof(sLogPath), "logs/rcon.attempts%s.log", sTime);
	LogToFile(sLogPath, sBuffer);
}