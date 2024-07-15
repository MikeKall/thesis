import openpyxl
import shutil
import openpyxl.styles
import aspose.cells as ac

class Reporter():

    def __init__(self, xlsx_file):
        self.xlsx_file = xlsx_file
        shutil.copyfile("report_template.xlsx", xlsx_file)
        self.wb = openpyxl.load_workbook(xlsx_file)
        self.ws = self.wb.active
        self.font_family = 'Calibri'
        self.ws[f'B1'].font = openpyxl.styles.Font(name=self.font_family, sz=12, bold=True)
        self.ws[f'D1'].font = openpyxl.styles.Font(name=self.font_family, sz=12, bold=True)
        self.ws[f'G1'].font = openpyxl.styles.Font(name=self.font_family, sz=12, bold=True)
        
        
    def create_services_report(self, active_service_vulnerabilities, possible_service_vulnerabilities):
        
        offset = 8
        NameLabel_cell = 3
        SeviceName_cell = 3
        VulnLabel_cell = 4
        CVE_cell = 5
        Exploitability_cell = 6
        Impact_cell = 7
        Version_cell = 8
        Severity_cell = 9

        for service_name in active_service_vulnerabilities:
            self.ws[f'B{SeviceName_cell}'].value = service_name
            self.ws[f'B{CVE_cell}'] = active_service_vulnerabilities[service_name]["CVE"]
            self.ws[f'B{Exploitability_cell}'] = active_service_vulnerabilities[service_name]["Exploitability Score"]
            self.ws[f'B{Impact_cell}'] = active_service_vulnerabilities[service_name]["Impact Score"]
            self.ws[f'B{Version_cell}'] = active_service_vulnerabilities[service_name]["Service Version"]
            self.ws[f'B{Severity_cell}'] = active_service_vulnerabilities[service_name]["Severity"]

            if active_service_vulnerabilities[service_name]["Severity"] == "HIGH":
                self.ws[f'B{Severity_cell}'].fill = openpyxl.styles.PatternFill("solid", fgColor="d11818")
            elif active_service_vulnerabilities[service_name]["Severity"] == "MEDIUM":
                self.ws[f'B{Severity_cell}'].fill = openpyxl.styles.PatternFill("solid", fgColor="FFC300")
            elif active_service_vulnerabilities[service_name]["Severity"] == "LOW":
                self.ws[f'B{Severity_cell}'].fill = openpyxl.styles.PatternFill("solid", fgColor="ecec0a")

            NameLabel_cell += offset
            VulnLabel_cell += offset
            SeviceName_cell += offset
            CVE_cell += offset
            Exploitability_cell += offset
            Impact_cell += offset
            Version_cell += offset
            Severity_cell += offset
        
        for service_name in possible_service_vulnerabilities:
            self.ws.merge_cells(f"B{NameLabel_cell}:C{NameLabel_cell}")

            self.ws[f'B{SeviceName_cell}'].value = service_name
            self.ws[f'C{CVE_cell}'] = possible_service_vulnerabilities[service_name]["CVE"]
            self.ws[f'C{Exploitability_cell}'] = possible_service_vulnerabilities[service_name]["Exploitability Score"]
            self.ws[f'C{Impact_cell}'] = possible_service_vulnerabilities[service_name]["Impact Score"]
            self.ws[f'C{Version_cell}'] = possible_service_vulnerabilities[service_name]["Service Version"]
            self.ws[f'C{Severity_cell}'] = possible_service_vulnerabilities[service_name]["Severity"]       

            if possible_service_vulnerabilities[service_name]["Severity"] == "HIGH":
                self.ws[f'C{Severity_cell}'].fill = openpyxl.styles.PatternFill("solid", fgColor="d11818")
            elif possible_service_vulnerabilities[service_name]["Severity"] == "MEDIUM":
                self.ws[f'C{Severity_cell}'].fill = openpyxl.styles.PatternFill("solid", fgColor="FFC300")
            elif possible_service_vulnerabilities[service_name]["Severity"] == "LOW":
                self.ws[f'C{Severity_cell}'].fill = openpyxl.styles.PatternFill("solid", fgColor="ecec0a")
            
            NameLabel_cell += offset
            VulnLabel_cell += offset
            SeviceName_cell += offset
            CVE_cell += offset
            Exploitability_cell += offset
            Impact_cell += offset
            Version_cell += offset
            Severity_cell += offset

            
        limit = len(possible_service_vulnerabilities) if len(possible_service_vulnerabilities) >= len(active_service_vulnerabilities) else len(active_service_vulnerabilities)
        i = 0
        NameLabel_cell = 3
        SeviceName_cell = 3
        VulnLabel_cell = 4
        CVE_cell = 5
        Exploitability_cell = 6
        Impact_cell = 7
        Version_cell = 8
        Severity_cell = 9
        while i < limit:
            self.ws.merge_cells(f"B{NameLabel_cell}:C{NameLabel_cell}")

            self.ws[f'A{NameLabel_cell}'] = 'Service Name'
            self.ws[f'B{VulnLabel_cell}'] = 'Active Vulnerabilities'
            self.ws[f'C{VulnLabel_cell}'] = 'Possible Vulnerabilities'
            self.ws[f'A{CVE_cell}'] = "CVE"
            self.ws[f'A{Exploitability_cell}'] = "Exploitability Score"
            self.ws[f'A{Impact_cell}'] = "Impact Score"
            self.ws[f'A{Version_cell}'] = "Service Version"
            self.ws[f'A{Severity_cell}'] = "Severity"

            # Set style
            self.ws[f'A{SeviceName_cell}'].font = openpyxl.styles.Font(name=self.font_family, bold=True)
            self.ws[f'A{CVE_cell}'].font = openpyxl.styles.Font(name=self.font_family, bold=True)
            self.ws[f'A{Exploitability_cell}'].font = openpyxl.styles.Font(name=self.font_family, bold=True)
            self.ws[f'A{Impact_cell}'].font = openpyxl.styles.Font(name=self.font_family, bold=True)
            self.ws[f'A{Version_cell}'].font = openpyxl.styles.Font(name=self.font_family, bold=True)
            self.ws[f'A{Severity_cell}'].font = openpyxl.styles.Font(name=self.font_family, bold=True)

            self.ws[f'B{SeviceName_cell}'].font = openpyxl.styles.Font(name=self.font_family, bold=True)
            self.ws[f'B{VulnLabel_cell}'].font = openpyxl.styles.Font(name=self.font_family)
            self.ws[f'B{CVE_cell}'].font = openpyxl.styles.Font(name=self.font_family)
            self.ws[f'B{Exploitability_cell}'].font = openpyxl.styles.Font(name=self.font_family)
            self.ws[f'B{Impact_cell}'].font = openpyxl.styles.Font(name=self.font_family)
            self.ws[f'B{Version_cell}'].font = openpyxl.styles.Font(name=self.font_family)
            self.ws[f'B{Severity_cell}'].font = openpyxl.styles.Font(name=self.font_family)

            self.ws[f'C{VulnLabel_cell}'].font = openpyxl.styles.Font(name=self.font_family)
            self.ws[f'C{CVE_cell}'].font = openpyxl.styles.Font(name=self.font_family)
            self.ws[f'C{Exploitability_cell}'].font = openpyxl.styles.Font(name=self.font_family)
            self.ws[f'C{Impact_cell}'].font = openpyxl.styles.Font(name=self.font_family)
            self.ws[f'C{Version_cell}'].font = openpyxl.styles.Font(name=self.font_family)
            self.ws[f'C{Severity_cell}'].font = openpyxl.styles.Font(name=self.font_family)

            # Allign cells
            self.ws[f'B{SeviceName_cell}'].alignment = openpyxl.styles.Alignment(horizontal='center')
            self.ws[f'A{NameLabel_cell}'].alignment = openpyxl.styles.Alignment(horizontal='center')
            self.ws[f'B{VulnLabel_cell}'].alignment = openpyxl.styles.Alignment(horizontal='center')
            self.ws[f'C{VulnLabel_cell}'].alignment = openpyxl.styles.Alignment(horizontal='center')

            self.ws[f'A{SeviceName_cell}'].alignment = openpyxl.styles.Alignment(horizontal='right')
            self.ws[f'A{CVE_cell}'].alignment = openpyxl.styles.Alignment(horizontal='right')
            self.ws[f'A{Exploitability_cell}'].alignment = openpyxl.styles.Alignment(horizontal='right')
            self.ws[f'A{Impact_cell}'].alignment = openpyxl.styles.Alignment(horizontal='right')
            self.ws[f'A{Version_cell}'].alignment = openpyxl.styles.Alignment(horizontal='right')
            self.ws[f'A{Severity_cell}'].alignment = openpyxl.styles.Alignment(horizontal='right')

            self.ws[f'C{CVE_cell}'].alignment = openpyxl.styles.Alignment(horizontal='left')
            self.ws[f'C{Exploitability_cell}'].alignment = openpyxl.styles.Alignment(horizontal='left')
            self.ws[f'C{Impact_cell}'].alignment = openpyxl.styles.Alignment(horizontal='left')
            self.ws[f'C{Version_cell}'].alignment = openpyxl.styles.Alignment(horizontal='left')
            self.ws[f'C{Severity_cell}'].alignment = openpyxl.styles.Alignment(horizontal='left')

            NameLabel_cell += offset
            VulnLabel_cell += offset
            SeviceName_cell += offset
            CVE_cell += offset
            Exploitability_cell += offset
            Impact_cell += offset
            Version_cell += offset
            Severity_cell += offset
            i += 1

        # Save the workbook
        self.wb.save(self.xlsx_file)
    
    def create_user_report(self, vulnerable_users, high_privilaged_users):
        starting_cell = 4
        self.ws[f'F{starting_cell-1}'].font = openpyxl.styles.Font(name=self.font_family, bold=True)
        self.ws[f'E{starting_cell-1}'].font = openpyxl.styles.Font(name=self.font_family, bold=True)

        for user in high_privilaged_users:
            self.ws[f'F{starting_cell}'] = f"{user} member of {high_privilaged_users[user]}"
            self.ws[f'F{starting_cell}'].font = openpyxl.styles.Font(name=self.font_family)
            self.ws[f'F{starting_cell}'].fill = openpyxl.styles.PatternFill("solid", fgColor="d11818")
            starting_cell += 1
        
        starting_cell = 4
        for user in vulnerable_users:
            if not user in high_privilaged_users:
                self.ws[f'E{starting_cell}'] = user
                self.ws[f'E{starting_cell}'].font = openpyxl.styles.Font(name=self.font_family)
                self.ws[f'E{starting_cell}'].fill = openpyxl.styles.PatternFill("solid", fgColor="ecec0a")
                starting_cell += 1
        
        self.wb.save(self.xlsx_file)

    def create_conf_report(self, configurations):
        recom_cell = 6
        serviceName_cell = recom_cell-3
        confFile_cell = recom_cell-2
        
        self.ws[f'H{serviceName_cell}'].font = openpyxl.styles.Font(name=self.font_family, bold=True)
        self.ws[f'I{serviceName_cell}'].font = openpyxl.styles.Font(name=self.font_family, bold=True)
        self.ws[f'H{confFile_cell}'].font = openpyxl.styles.Font(name=self.font_family, bold=True)
        self.ws[f'I{confFile_cell}'].font = openpyxl.styles.Font(name=self.font_family, bold=True)
        self.ws[f'I{recom_cell-1}'].font = openpyxl.styles.Font(name=self.font_family, bold=True)
        for service in configurations:
            if configurations[service]:
                self.ws[f'I{confFile_cell-1}'] = service
                self.ws[f'H{confFile_cell-1}'] = "Service"
                self.ws[f'I{confFile_cell-1}'].font = openpyxl.styles.Font(name=self.font_family, bold=True)
                self.ws[f'H{confFile_cell-1}'].font = openpyxl.styles.Font(name=self.font_family, bold=True)
                if service in ["Apache", "PostgreSQL"]:
                    for file in configurations[service]:
                        if configurations[service][file]:
                            self.ws[f'H{confFile_cell}'] = "Configuration File"
                            self.ws[f'I{confFile_cell}'] = file
                            self.ws[f'I{recom_cell-1}'] = "Recommendations"
                            self.ws[f'H{confFile_cell}'].font = openpyxl.styles.Font(name=self.font_family, bold=True)
                            self.ws[f'I{confFile_cell}'].font = openpyxl.styles.Font(name=self.font_family, bold=True)
                            self.ws[f'I{recom_cell-1}'].font = openpyxl.styles.Font(name=self.font_family, bold=True)

                            for configuration in configurations[service][file].values():
                                if not isinstance(configuration, bool):
                                    if "Warning" in configuration:
                                        self.ws[f'C{recom_cell}'].fill = openpyxl.styles.PatternFill("solid", fgColor="ecec0a")

                                    self.ws[f'I{recom_cell}'] = configuration
                                    self.ws[f'I{recom_cell}'].font = openpyxl.styles.Font(name=self.font_family)
                                    recom_cell += 1
                            recom_cell += 2
                            confFile_cell = recom_cell-2
                else:
                    for reg_key in configurations[service]:
                        index = 0
                        self.ws[f'H{recom_cell-2}'] = "Registry Key"
                        self.ws[f'I{recom_cell-2}'] = reg_key
                        self.ws[f'I{recom_cell-1}'] = "Needs review"
                        self.ws[f'H{recom_cell-2}'].font = openpyxl.styles.Font(name=self.font_family, bold=True)
                        self.ws[f'I{recom_cell-2}'].font = openpyxl.styles.Font(name=self.font_family, bold=True)
                        self.ws[f'I{recom_cell-1}'].font = openpyxl.styles.Font(name=self.font_family, bold=True)
                        while index < len(configurations[service][reg_key]):
                            configurations[service][reg_key][index]
                            if configurations[service][reg_key][index]:
                                self.ws[f'I{recom_cell}'] = configurations[service][reg_key][index]
                                self.ws[f'I{recom_cell}'].font = openpyxl.styles.Font(name=self.font_family)
                                recom_cell += 1
                            index += 1
                        recom_cell += 3
                        confFile_cell = recom_cell-2
                            
            
        self.wb.save(self.xlsx_file)

    def xlsx_to_pdf(self, pdf_file):
        workbook = ac.Workbook(self.xlsx_file)
        pdfOptions = ac.PdfSaveOptions()
        pdfOptions.all_columns_in_one_page_per_sheet = True
        workbook.save(pdf_file, pdfOptions)