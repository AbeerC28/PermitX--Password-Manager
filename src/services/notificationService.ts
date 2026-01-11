export async function sendAdminNotification(type: string, data: any = {}): Promise<{ email?: boolean; sms?: boolean }> {
  console.log(`Admin notification would be sent: ${type}`, data);
  return { email: true };
}

export async function sendUserNotification(type: string, userEmail: string, data: any = {}): Promise<{ email?: boolean }> {
  console.log(`User notification would be sent to ${userEmail}: ${type}`, data);
  return { email: true };
}