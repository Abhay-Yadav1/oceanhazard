Frontend Files Description:
->User Interface (Citizen)
->templates/user/index.html - Main reporting form with hazard selection, description, location, and media upload

->templates/user/success.html - Success confirmation after report submission

->static/css/user.css - Mobile-friendly styles for reporting interface

->static/js/user/geolocation.js - Browser location capture

->static/js/user/offline.js - Offline storage functionality

->static/js/user/upload.js - Media upload handling

->static/js/user/main.js - User form validation and submission



Verifier Interface (Local Officers)
templates/verifier/login.html - Simple login form

templates/verifier/dashboard.html - List of reports to verify with filters

templates/verifier/report_detail.html - Detailed report view for verification

static/css/verifier.css - Clean, efficient interface for verification workflow

static/js/verifier/dashboard.js - Report filtering and management

static/js/verifier/verification.js - Verification actions and status updates

static/js/verifier/main.js - Verifier application logic



Admin Interface (Government/INCOIS)
templates/admin/login.html - Admin login form

templates/admin/dashboard.html - Overview of all reports and system status

templates/admin/analytics.html - Data visualization and insights

static/css/admin.css - Professional dashboard-style interface

static/js/admin/dashboard.js - Data display and management

static/js/admin/analytics.js - Charts and data visualization

static/js/admin/main.js - Admin application logic



Shared Components
templates/base.html - Common layout with header, navigation, and footer

static/css/main.css - Global styles and design system

static/js/shared/utils.js - Utility functions used across interfaces

static/js/shared/api.js - API communication helpers