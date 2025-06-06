# API Documentation System

A modern, macOS-inspired API documentation management system built with Node.js, Express, and EJS templating. This application provides a beautiful, responsive interface for managing and viewing API documentation with role-based access control.

## 📸 Screenshots

### Login Page
![Login Page](/public/readme/login.png)
*Clean, macOS-inspired login interface with demo accounts*

### Home Page
![Home Page](/public/readme/home.png)
*Main dashboard with sidebar navigation and welcome screen*

### API Detail Page
![API Detail Page](/public/readme/detail.png)
*Comprehensive endpoint documentation with all parameters*

## ✨ Features

### 🎨 Design & UI
- **macOS Native Design** - Authentic macOS window controls, typography, and styling
- **Responsive Layout** - Perfect on desktop, tablet, and mobile devices
- **Dark/Light Theme** - Clean, professional appearance
- **Smooth Animations** - 60fps transitions and micro-interactions

### 🔐 Authentication & Security
- **Session-based Authentication** - Secure login system
- **Role-based Access Control** - Admin, User, Guest roles
- **Demo Accounts** - Pre-configured test users
- **Logout Functionality** - Secure session management

### 📚 API Documentation Management
- **CRUD Operations** - Create, Read, Update, Delete endpoints
- **Rich Parameter Support**:
  - Request Body (JSON)
  - URL Parameters
  - Query Parameters
  - Request Headers
  - Access Roles
  - Response Examples
  - cURL Examples
- **Grouping System** - Organize endpoints by categories
- **Search Functionality** - Real-time search with dropdown suggestions

### 📱 Mobile Experience
- **Hamburger Menu** - Collapsible sidebar for mobile
- **Touch-friendly Interface** - Optimized for touch devices
- **Responsive Tables** - Horizontal scroll for parameter tables
- **Mobile Modals** - Full-screen modals on small devices

### 🛠️ Technical Features
- **JSON Data Storage** - File-based data persistence
- **RESTful API** - Clean API endpoints for data management
- **Error Handling** - Comprehensive error pages
- **Form Validation** - Client and server-side validation

## 🏗️ Architecture & Design Patterns

### **MVC Pattern (Model-View-Controller)**
```
├── routes/          # Controllers - Handle HTTP requests
├── views/           # Views - EJS templates
├── data/            # Models - JSON data storage
└── public/          # Static assets
```

### **Design Patterns Used**

1. **Template Method Pattern** - EJS templating system
2. **Middleware Pattern** - Express.js middleware for authentication
3. **Observer Pattern** - Event-driven form handling
4. **Factory Pattern** - Dynamic modal creation
5. **Singleton Pattern** - Session management

### **Frontend Architecture**
- **Progressive Enhancement** - Works without JavaScript
- **Mobile-First Design** - Responsive breakpoints
- **Component-Based CSS** - Modular styling approach
- **Semantic HTML** - Accessible markup structure

## 🚀 Installation & Setup

### Prerequisites
- Node.js (v14 or higher)
- npm or yarn

### Quick Start

1. **Clone the repository**
```bash
git clone <repository-url>
cd api-docs
```

2. **Install dependencies**
```bash
npm install
```

3. **Start the application**
```bash
npm start
```

4. **Access the application**
```
http://localhost:3000
```

### Demo Accounts

| Username | Password | Role | Description |
|----------|----------|------|-------------|
| `ahmet` | `ahmet123` | Admin | Full access to all features |
| `bora` | `bora123` | User | Read-only access |
| `emre` | `emre123` | User | Read-only access |

## 📁 Project Structure

```
api-docs/
├── app.js                 # Main application file
├── package.json           # Dependencies and scripts
├── routes/
│   └── index.js          # API routes and authentication
├── views/
│   ├── index.ejs         # Main dashboard
│   ├── login.ejs         # Login page
│   └── error.ejs         # Error page
├── data/
│   ├── data.json         # API endpoints data
│   └── user.json         # User accounts
└── README.md             # This file
```

## 🎯 Key Components

### Authentication System
- Session-based authentication with Express sessions
- Role-based middleware for route protection
- Secure password handling (ready for bcrypt integration)

### API Management
- Full CRUD operations for endpoints
- JSON schema validation
- Dynamic form generation
- Real-time search and filtering

### Responsive Design
- CSS Grid and Flexbox layouts
- Mobile-first breakpoints:
  - Desktop: 1024px+
  - Tablet: 768px - 1024px
  - Mobile: 480px - 768px
  - Small Mobile: 320px - 480px

## 🔧 Configuration

### Environment Variables
```bash
PORT=3000                 # Server port
SESSION_SECRET=your-secret # Session encryption key
NODE_ENV=development      # Environment mode
```

### Data Structure

#### Endpoint Schema
```json
{
  "id": "unique-id",
  "method": "GET|POST|PUT|DELETE",
  "endpoint": "/api/path",
  "description": "Endpoint description",
  "group": "Category name",
  "roles": ["guest", "user", "admin"],
  "body": { "param": "description" },
  "params": { "param": "description" },
  "query": { "param": "description" },
  "headers": { "header": "description" },
  "response": { "example": "response" },
  "cURL": "curl command example"
}
```

#### User Schema
```json
{
  "id": 1,
  "name": "Full Name",
  "username": "username",
  "password": "password",
  "role": "admin|user|guest"
}
```

## 🎨 Design System

### Colors
- **Primary Blue**: `#007aff` - Links, buttons, accents
- **Background**: `#f0f0f0` - Main background
- **Surface**: `#ffffff` - Cards, modals
- **Text Primary**: `#1d1d1f` - Main text
- **Text Secondary**: `#8e8e93` - Secondary text

### Typography
- **Font Family**: SF Pro Display, system fonts
- **Weights**: 300, 400, 500, 600, 700
- **Responsive scaling** with proper line heights

### Components
- **Buttons**: Rounded corners, hover states
- **Forms**: Clean inputs with focus states
- **Modals**: Centered with backdrop blur
- **Tables**: Responsive with horizontal scroll

## 🚀 API Endpoints

### Authentication
- `GET /login` - Login page
- `POST /login` - Authenticate user
- `POST /logout` - End session

### API Management
- `GET /` - Main dashboard
- `GET /api/endpoints` - Get all endpoints
- `POST /api/endpoints` - Create endpoint
- `PUT /api/endpoints/:id` - Update endpoint
- `DELETE /api/endpoints/:id` - Delete endpoint

### User Management (Admin only)
- `GET /api/users` - Get all users
- `POST /api/users` - Create user
- `PUT /api/users/:id` - Update user
- `DELETE /api/users/:id` - Delete user

## 🔍 Features in Detail

### Search System
- **Real-time filtering** as you type
- **Multi-field search** (endpoint, method, description, group)
- **Dropdown suggestions** with method badges
- **Keyboard navigation** support

### Role System
- **Visual badges** for each role type
- **Color-coded indicators**:
  - Guest: Gray
  - User: Blue
  - Admin: Red
  - Moderator: Purple
  - Developer: Green

### Mobile Navigation
- **Hamburger menu** for mobile devices
- **Slide-out sidebar** with smooth animations
- **Overlay background** when menu is open
- **Auto-close** when selecting items

## 🛠️ Development

### Adding New Features
1. Update data schema in `/data/`
2. Add routes in `/routes/index.js`
3. Update views in `/views/`
4. Add CSS styles for new components

### Customization
- **Colors**: Update CSS custom properties
- **Fonts**: Modify font imports and family declarations
- **Layout**: Adjust responsive breakpoints
- **Features**: Add new endpoint parameters

## 📱 Browser Support

- **Chrome**: 90+
- **Firefox**: 88+
- **Safari**: 14+
- **Edge**: 90+
- **Mobile Safari**: iOS 14+
- **Chrome Mobile**: Android 10+

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- **Apple Design Guidelines** - For design inspiration
- **macOS Human Interface Guidelines** - For UI patterns
- **Express.js Community** - For the robust framework
- **EJS Template Engine** - For server-side rendering

## 📞 Support

For support, please open an issue on GitHub or contact the development team.

---

**Built with ❤️ using Node.js, Express, and modern web technologies**
