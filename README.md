# Finish-BDE
 Accepts parameters to complete BDE in one script.

########################################################################
#																		
	Script Title: Finish-BDE											
	Author: Brennan Custard												
	Date: 8/26/2020														
	Description: This script accepts basic parameters to complete		
	the BDE process for a given OS disk in an endpoint.			 		
																		
########################################################################
#
#	This script makes several assumptions.
		1. The password or PIN must be at least 8 or 6 characters respectively.
		2. If NewPIN is not specified, you want to use the last 6 of the 
			serial number (all caps) as	the first PIN.
		3. If NewPassword is not specified, you want to use a provided 
			CompanyIdentifier paramater plus the last 6 of the serial
			number (all caps) as the first password.
		4. By default a RecoveryPasswordProtector should be added.
		5. By default a hardware test will be performed before encryption
#
########################################################################