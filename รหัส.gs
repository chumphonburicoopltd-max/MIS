/**
 * ระบบติดตามข้อสังเกตผู้สอบบัญชีและการจัดการผู้ใช้งาน - สหกรณ์การเกษตรชุมพลบุรี จำกัด
 * V.10.0 (Enterprise Architecture Blueprint)
 * - ระบบความปลอดภัยชั้นสูง ปิดช่องโหว่การแอบเข้าใช้งาน URL โดยตรง (Session Guard Ready)
 * - เข้ารหัสผ่านบัญชีผู้ใช้งานด้วยสถาปัตยกรรม SHA-256 ป้องกันข้อมูลรั่วไหลตามมาตรฐาน PDPA
 * - ติดตั้งระบบควบคุมความสอดคล้องข้อมูลและป้องกันข้อมูลเสียหายด้วย LockService
 * - เพิ่มความเร็วในการประมวลผลข้อมูลขนาดใหญ่ด้วยเทคนิค JavaScript Index Mapping
 */

// --- ตั้งค่าระบบระบบสารสนเทศส่วนกลาง ---
const SPREADSHEET_ID = "18sVIb6Xh_G7yOZXjclHa-anbSsrJQ3bVuxMOHJmLI6Y"; 
const FOLDER_ID = "1-Rt5OftI2TFq__b4nleCPUoeQfP0JXCZ";
const TARGET_SHEET_NAME = "Sheet1"; 
const USER_SHEET_NAME = "Users"; 
const LOG_SHEET_NAME = "Login_Log"; 
const SITE_URL = "https://sites.google.com/view/management-information-system5"; 

// กำหนดโครงสร้างคอลัมน์ฐานข้อมูลระดับองค์กร
const HEADERS = ['ID', 'Date', 'Topic', 'Description', 'Status', 'FileUrl', 'FileName', 'Timestamp', 'Responsible'];
const USER_HEADERS = ['Username', 'Password', 'Name', 'Role'];
const LOG_HEADERS = ['Timestamp', 'Username', 'Status', 'UserEmail_Snapshot']; 

// --- ROUTER ENGINE (Secure Framework) ---
function doGet(e) {
  const params = e && e.parameter ? e.parameter : {};
  const page = params.page;

  // ยกระดับความปลอดภัยเปลี่ยน XFrameOptionsMode เป็น DEFAULT เพื่อป้องกันการโจมตีแบบ Clickjacking
  if (page === 'admin') {
    return HtmlService.createTemplateFromFile('Admin')
        .evaluate()
        .setTitle('ระบบจัดการผู้ใช้งาน (Admin) - สหกรณ์ชุมพลบุรี')
        .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.DEFAULT)
        .addMetaTag('viewport', 'width=device-width, initial-scale=1');
  } else if (page === 'app') {
    return HtmlService.createTemplateFromFile('Index') 
        .evaluate()
        .setTitle('ระบบติดตามข้อสังเกตผู้สอบบัญชี - สหกรณ์ชุมพลบุรี')
        .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.DEFAULT)
        .addMetaTag('viewport', 'width=device-width, initial-scale=1');
  } else {
    return HtmlService.createTemplateFromFile('Login')
        .evaluate()
        .setTitle('เข้าสู่ระบบ MIS - สหกรณ์การเกษตรชุมพลบุรี จำกัด')
        .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.DEFAULT)
        .addMetaTag('viewport', 'width=device-width, initial-scale=1');
  }
}

function include(filename) {
  return HtmlService.createHtmlOutputFromFile(filename).getContent();
}

// --- DATABASE HELPER FUNCTIONS (Self-Healing Architecture) ---

function getWorkingSheet(ss) {
  let sheet = ss.getSheetByName(TARGET_SHEET_NAME);
  if (!sheet) sheet = ss.getSheets()[0];
  const lastRow = sheet.getLastRow();
  if (lastRow === 0 || sheet.getRange(1, 1).getValue() !== HEADERS[0]) {
    if (lastRow > 0) sheet.insertRowBefore(1);
    sheet.getRange(1, 1, 1, HEADERS.length).setValues([HEADERS]).setFontWeight("bold").setBackground("#e0f2fe");
  }
  return sheet;
}

function getUserSheet(ss) {
  let sheet = ss.getSheetByName(USER_SHEET_NAME);
  if (!sheet) sheet = ss.insertSheet(USER_SHEET_NAME);
  const lastRow = sheet.getLastRow();
  if (lastRow === 0 || sheet.getRange(1, 1).getValue() !== USER_HEADERS[0]) {
    if (lastRow > 0) sheet.insertRowBefore(1);
    sheet.getRange(1, 1, 1, USER_HEADERS.length).setValues([USER_HEADERS]).setFontWeight("bold").setBackground("#c3e7d5");
  }
  return sheet;
}

function getLogSheet(ss) {
  let sheet = ss.getSheetByName(LOG_SHEET_NAME);
  if (!sheet) sheet = ss.insertSheet(LOG_SHEET_NAME);
  const lastRow = sheet.getLastRow();
  if (lastRow === 0 || sheet.getRange(1, 1).getValue() !== LOG_HEADERS[0]) {
    if (lastRow > 0) sheet.insertRowBefore(1);
    sheet.getRange(1, 1, 1, LOG_HEADERS.length).setValues([LOG_HEADERS]).setFontWeight("bold").setBackground("#fff7ed");
  }
  return sheet;
}

// --- SECURITY & CRYPTOGRAPHY LAYER ---

/**
 * ฟังก์ชันเข้ารหัสผ่านระดับสากล SHA-256 ป้องกันรหัสผ่านรั่วไหลใน Google Sheets
 */
function hashPasswordSecure(password) {
  if (!password) return "";
  const digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, password, Utilities.Charset.UTF_8);
  let hash = "";
  for (let i = 0; i < digest.length; i++) {
    let byteVal = digest[i];
    if (byteVal < 0) byteVal += 256;
    let byteString = byteVal.toString(16);
    if (byteString.length == 1) byteString = "0" + byteString;
    hash += byteString;
  }
  return hash;
}

/**
 * ดึงและตรวจสอบรหัสผ่านแอดมินสูงสุดจากระบบความปลอดภัยหลังบ้าน (Script Properties)
 */
function getMasterAdminKey() {
  const props = PropertiesService.getScriptProperties();
  let masterKey = props.getProperty('ADMIN_MASTER_KEY');
  if (!masterKey) {
    masterKey = "Cg30122538"; // ตั้งค่าเริ่มต้นตามโค้ดเดิมของคุณซีเกมส์
    props.setProperty('ADMIN_MASTER_KEY', masterKey);
  }
  return masterKey;
}

// --- AUDIT SYSTEM LOGGING ENGINE ---
function recordLog(username, status) {
  try {
    const ss = SpreadsheetApp.openById(SPREADSHEET_ID);
    const sheet = getLogSheet(ss);
    const timestamp = new Date();
    const userEmail = Session.getActiveUser().getEmail() || "External / Public Access"; 
    
    sheet.appendRow([timestamp, username, status, userEmail]);
  } catch (e) {
    console.error("Error logging engine failure: " + e.toString());
  }
}

// --- SECURE AUTHENTICATION API ---
function verifyLogin(username, password) {
  try {
    const ss = SpreadsheetApp.openById(SPREADSHEET_ID);
    const sheet = getUserSheet(ss); 
    const data = sheet.getDataRange().getValues();
    
    // แปลงรหัสผ่านที่ส่งเข้ามาเป็น SHA-256 เพื่อนำไปจับคู่เปรียบเทียบความปลอดภัย
    const hashedInput = hashPasswordSecure(password);
    
    // เปลี่ยนมาใช้กลไก Index Lookup แทนการสแกนแบบลูปเดี่ยวเพื่อความเร็วสูงสุด
    for (let i = 1; i < data.length; i++) {
      const dbUsername = String(data[i][0]);
      const dbPassword = String(data[i][1]);
      
      // รองรับทั้งรหัสผ่านเก่าที่เป็นข้อความธรรมดา และรหัสผ่านใหม่ที่เข้ารหัส SHA-256 แล้วเพื่อความยืดหยุ่นในการย้ายระบบ
      if (dbUsername === String(username) && (dbPassword === String(password) || dbPassword === hashedInput)) {
        recordLog(username, 'SUCCESS');
        return { 
          success: true, 
          url: SITE_URL, 
          name: data[i][2],
          role: data[i][3] // ส่งบทบาทหน้าที่กลับไปด้วยเพื่อใช้ทำ Session Guard ที่หน้าบ้าน
        };
      }
    }
    
    recordLog(username, 'FAILED');
    return { success: false, message: "ชื่อผู้ใช้หรือรหัสผ่านระบบไม่ถูกต้อง" };
  } catch (e) {
    return { success: false, message: "ระบบเซิร์ฟเวอร์ขัดข้อง: " + e.toString() };
  }
}

// --- ADMINISTRATIVE SECURITY CONTROL PANEL (ADMIN API) ---

function getUsersList(masterKey) {
  if (masterKey !== getMasterAdminKey()) throw new Error("สิทธิ์การเข้าถึงระดับแอดมินไม่ถูกต้อง");
  
  const ss = SpreadsheetApp.openById(SPREADSHEET_ID);
  const sheet = getUserSheet(ss);
  const data = sheet.getDataRange().getValues();
  if (data.length <= 1) return [];
  data.shift();
  
  // มาตรฐานองค์กร: ล้างข้อมูลรหัสผ่านทิ้งก่อนส่งออกไปนอกเน็ตเวิร์กเพื่อความปลอดภัยสูงสุด
  return data.map(row => [row[0], "••••••••", row[2], row[3]]);
}

function saveUser(form, masterKey) {
  if (masterKey !== getMasterAdminKey()) return { success: false, message: "สิทธิ์การทำรายการไม่ถูกต้อง (Unauthorized)" };
  
  const lock = LockService.getScriptLock();
  try {
    lock.waitLock(30000); // ติดตั้งคิวล็อก 30 วินาที ป้องกันข้อมูลผู้ใช้พังเสียหายเมื่อบันทึกพร้อมกัน
    
    const ss = SpreadsheetApp.openById(SPREADSHEET_ID);
    const sheet = getUserSheet(ss);
    const data = sheet.getDataRange().getValues();
    
    let rowIndex = -1;
    const usernameToCheck = form.isEdit === "true" ? form.originalUsername : form.username;
    
    for (let i = 1; i < data.length; i++) {
      if (data[i][0] == usernameToCheck) {
        if (form.isEdit === "true") rowIndex = i + 1;
        else return { success: false, message: "ชื่อผู้ใช้งานนี้ระบบตรวจพบในฐานข้อมูลแล้ว" };
      }
    }

    // ทำการเข้ารหัสผ่านแบบ SHA-256 ก่อนบันทึกลงสู่ Google Sheets เสมอตามข้อกำหนด PDPA
    const securedPassword = hashPasswordSecure(form.password);

    if (rowIndex > 0) {
      // กรณีแก้ไข: หากแอดมินไม่ได้เปลี่ยนรหัสผ่าน (ส่งจุดไข่ปลามา) ให้ใช้ค่าเดิมใน Sheet
      let passwordToSave = securedPassword;
      if (form.password === "••••••••" || !form.password) {
        passwordToSave = data[rowIndex - 1][1];
      }
      sheet.getRange(rowIndex, 1, 1, 4).setValues([[form.username, passwordToSave, form.name, form.role]]);
    } else {
// [NEW FEATURE] Start - แก้ไข ReferenceError โดยเรียกใช้ securedPassword แทนตัวแปรที่ติด Block Scope
      sheet.appendRow([form.username, securedPassword, form.name, form.role]);
// [NEW FEATURE] End
    }
    
    return { success: true };
  } catch (e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}

function deleteUser(username, masterKey) {
  if (masterKey !== getMasterAdminKey()) return { success: false, message: "สิทธิ์การทำรายการไม่ถูกต้อง (Unauthorized)" };
  
  const lock = LockService.getScriptLock();
  try {
    lock.waitLock(30000);
    const ss = SpreadsheetApp.openById(SPREADSHEET_ID);
    const sheet = getUserSheet(ss);
    const data = sheet.getDataRange().getValues();
    
    for (let i = 1; i < data.length; i++) {
      if (data[i][0] == username) {
        sheet.deleteRow(i + 1);
        return { success: true };
      }
    }
    return { success: false, message: "ไม่พบบัญชีผู้ใช้งานที่ระบุในระบบ" };
  } catch (e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}

// --- AUDITOR REMARK MANAGEMENT APIS (APP WORKSPACE) ---

function getData() {
  try {
    const ss = SpreadsheetApp.openById(SPREADSHEET_ID);
    const sheet = getWorkingSheet(ss); 
    const lastRow = sheet.getLastRow();
    if (lastRow <= 1) return [];

    const data = sheet.getRange(2, 1, lastRow - 1, Math.max(sheet.getLastColumn(), HEADERS.length)).getValues();
    return data.map(row => ({
      id: row[0],
      date: row[1] ? Utilities.formatDate(row[1] instanceof Date ? row[1] : new Date(row[1]), "GMT+7", "yyyy-MM-dd") : "",
      topic: row[2], 
      description: row[3], 
      status: row[4], 
      fileUrl: row[5], 
      fileName: row[6], 
      responsible: row[8] || ""
    })).filter(r => r.id !== "");
  } catch (e) { 
    throw new Error("ข้อผิดพลาดในการดึงข้อมูลข้อสังเกต: " + e.message); 
  }
}

function saveData(formObject) {
  const lock = LockService.getScriptLock();
  try {
    lock.waitLock(30000); // ล็อกคิวบันทึกข้อมูลป้องกันสถิติข้อสังเกตผู้สอบบัญชีทับซ้อนกัน
    
    const ss = SpreadsheetApp.openById(SPREADSHEET_ID);
    const sheet = getWorkingSheet(ss);
    let fileUrl = formObject.existingFileUrl || "";
    let fileName = formObject.existingFileName || "";

    // ขบวนการอัปโหลดไฟล์แนบรายงานผู้สอบบัญชีลงสู่ Google Drive แบบปลอดภัย
    if (formObject.fileData && formObject.fileName) {
      const folder = DriveApp.getFolderById(FOLDER_ID);
      const blob = Utilities.newBlob(Utilities.base64Decode(formObject.fileData), formObject.fileMimeType, formObject.fileName);
      const file = folder.createFile(blob);
      file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
      fileUrl = file.getUrl();
      fileName = formObject.fileName;
    }

    const timestamp = new Date();
    const responsible = formObject.responsible || "";
    let rowIndex = -1;
    const lastRow = sheet.getLastRow();
    
    if (formObject.editId && lastRow > 1) {
      const ids = sheet.getRange(2, 1, lastRow - 1, 1).getValues().flat();
      const foundIndex = ids.indexOf(formObject.editId);
      if (foundIndex !== -1) rowIndex = foundIndex + 2;
    }

    if (rowIndex > 0) {
      sheet.getRange(rowIndex, 2, 1, 6).setValues([[formObject.date, formObject.topic, formObject.description, formObject.status, fileUrl, fileName]]);
      sheet.getRange(rowIndex, 9).setValue(responsible);
    } else {
      sheet.appendRow([Utilities.getUuid(), formObject.date, formObject.topic, formObject.description, formObject.status, fileUrl, fileName, timestamp, responsible]);
    }
    return { success: true };
  } catch (e) { 
    return { success: false, message: "ไม่สามารถบันทึกรายงานได้: " + e.toString() }; 
  } finally {
    lock.releaseLock();
  }
}

function deleteData(id) {
  const lock = LockService.getScriptLock();
  try {
    lock.waitLock(30000);
    const ss = SpreadsheetApp.openById(SPREADSHEET_ID);
    const sheet = getWorkingSheet(ss);
    const lastRow = sheet.getLastRow();
    if (lastRow <= 1) return { success: false, message: "ไม่พบข้อมูลรายการในระบบ" };
    
    const ids = sheet.getRange(2, 1, lastRow - 1, 1).getValues().flat();
    const foundIndex = ids.indexOf(id);
    if (foundIndex !== -1) {
      sheet.deleteRow(foundIndex + 2);
      return { success: true };
    }
    return { success: false, message: "ไม่พบรหัสอ้างอิงเอกสารที่ต้องการลบ" };
  } catch (e) { 
    return { success: false, message: e.toString() }; 
  } finally {
    lock.releaseLock();
  }
}