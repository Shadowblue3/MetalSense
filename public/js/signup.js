let currentUserType = 'public';

// District data for different states
const stateDistrictData = {
    'west-bengal': ['Kolkata', 'Howrah', 'North 24 Parganas', 'South 24 Parganas', 'Hooghly', 'Bardhaman', 'Nadia', 'Murshidabad'],
    'uttar-pradesh': ['Lucknow', 'Kanpur Nagar', 'Agra', 'Varanasi', 'Meerut', 'Allahabad', 'Bareilly', 'Moradabad'],
    'maharashtra': ['Mumbai', 'Pune', 'Nagpur', 'Thane', 'Nashik', 'Aurangabad', 'Solapur', 'Amravati'],
    'gujarat': ['Ahmedabad', 'Surat', 'Vadodara', 'Rajkot', 'Bhavnagar', 'Jamnagar', 'Gandhinagar', 'Anand'],
    'rajasthan': ['Jaipur', 'Jodhpur', 'Udaipur', 'Kota', 'Bikaner', 'Ajmer', 'Alwar', 'Bharatpur']
};

const villageData = {
    'Kolkata': ['Salt Lake', 'Ballygunge', 'Park Street', 'Howrah Bridge Area', 'New Town'],
    'Howrah': ['Shibpur', 'Liluah', 'Bally', 'Serampore', 'Rishra'],
    'North 24 Parganas': ['Barrackpore', 'Panihati', 'Kamarhati', 'Titagarh', 'Naihati'],
    // Add more villages for other districts as needed
};

function selectUserType(type) {
    currentUserType = type;

    // Update buttons
    document.getElementById('publicBtn').classList.toggle('active', type === 'public');
    document.getElementById('officialBtn').classList.toggle('active', type === 'official');

    // Show/hide forms
    document.getElementById('publicForm').classList.toggle('active', type === 'public');
    document.getElementById('officialForm').classList.toggle('active', type === 'official');

    // Update hidden input for server
    const ut = document.getElementById('userType');
    if (ut) ut.value = type;

    // Enable active section, disable inactive to avoid HTML5 validation conflicts
    const publicInputs = document.querySelectorAll('#publicForm input, #publicForm select, #publicForm textarea');
    const officialInputs = document.querySelectorAll('#officialForm input, #officialForm select, #officialForm textarea');
    if (type === 'public') {
        publicInputs.forEach(el => el.disabled = false);
        officialInputs.forEach(el => el.disabled = true);
    } else {
        publicInputs.forEach(el => el.disabled = true);
        officialInputs.forEach(el => el.disabled = false);
    }

    // Clear errors/strength
    document.querySelectorAll('.error-message').forEach(error => error.style.display = 'none');
    document.querySelectorAll('.password-strength').forEach(strength => strength.innerHTML = '');
}

function updateDistricts(userType) {
    const stateSelect = document.getElementById(userType + 'State');
    const districtSelect = document.getElementById(userType + 'District');
    const villageSelect = document.getElementById(userType + 'Village');

    const selectedState = stateSelect.value;

    // Clear district and village options
    districtSelect.innerHTML = '<option value="">Select District</option>';
    if (villageSelect) {
        villageSelect.innerHTML = '<option value="">Select Village/Area</option>';
    }

    if (selectedState && stateDistrictData[selectedState]) {
        stateDistrictData[selectedState].forEach(district => {
            const option = document.createElement('option');
            option.value = district.toLowerCase().replace(/\s+/g, '-');
            option.textContent = district;
            districtSelect.appendChild(option);
        });
    }
}

function updateVillages(userType) {
    const districtSelect = document.getElementById(userType + 'District');
    const villageSelect = document.getElementById(userType + 'Village');

    const selectedDistrict = districtSelect.options[districtSelect.selectedIndex].text;

    // Clear village options
    villageSelect.innerHTML = '<option value="">Select Village/Area</option>';

    if (selectedDistrict && villageData[selectedDistrict]) {
        villageData[selectedDistrict].forEach(village => {
            const option = document.createElement('option');
            option.value = village.toLowerCase().replace(/\s+/g, '-');
            option.textContent = village;
            villageSelect.appendChild(option);
        });
    }
}

function checkPasswordStrength(password, strengthElementId) {
    const strengthDiv = document.getElementById(strengthElementId);
    let score = 0;

    if (password.length >= 8) score++;
    if (password.match(/[a-z]/)) score++;
    if (password.match(/[A-Z]/)) score++;
    if (password.match(/[0-9]/)) score++;
    if (password.match(/[^a-zA-Z0-9]/)) score++;

    if (password.length === 0) {
        strengthDiv.innerHTML = '';
        return;
    }

    if (score < 3) {
        strengthDiv.innerHTML = '<span class="strength-weak">Weak password - Add uppercase, numbers, and symbols</span>';
    } else if (score < 5) {
        strengthDiv.innerHTML = '<span class="strength-medium">Medium password - Add more complexity</span>';
    } else {
        strengthDiv.innerHTML = '<span class="strength-strong">Strong password</span>';
    }
}

function validateForm() {
    let isValid = true;

    // Reset error messages
    document.querySelectorAll('.error-message').forEach(error => {
        error.style.display = 'none';
    });

    if (currentUserType === 'public') {
        // Validate public form
        const fullName = document.getElementById('publicFullName').value.trim();
        if (fullName.length < 2) {
            document.getElementById('publicFullNameError').style.display = 'block';
            isValid = false;
        }

        const mobile = document.getElementById('publicMobile').value.trim();
        const mobileRegex = /^[6-9]\d{9}$/;
        if (!mobileRegex.test(mobile)) {
            document.getElementById('publicMobileError').style.display = 'block';
            isValid = false;
        }

        const email = document.getElementById('publicEmail').value.trim();
        if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            document.getElementById('publicEmailError').style.display = 'block';
            isValid = false;
        }

        const state = document.getElementById('publicState').value;
        if (!state) {
            document.getElementById('publicStateError').style.display = 'block';
            isValid = false;
        }

        const district = document.getElementById('publicDistrict').value;
        if (!district) {
            document.getElementById('publicDistrictError').style.display = 'block';
            isValid = false;
        }

        const village = document.getElementById('publicVillage').value;
        if (!village) {
            document.getElementById('publicVillageError').style.display = 'block';
            isValid = false;
        }

        const password = document.getElementById('publicPassword').value;
        const strongPasswordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        if (!strongPasswordRegex.test(password)) {
            document.getElementById('publicPasswordError').style.display = 'block';
            isValid = false;
        }

        const confirmPassword = document.getElementById('publicConfirmPassword').value;
        if (password !== confirmPassword) {
            document.getElementById('publicConfirmPasswordError').style.display = 'block';
            isValid = false;
        }

    } else {
        // Validate official form
        const fullName = document.getElementById('officialFullName').value.trim();
        if (fullName.length < 2) {
            document.getElementById('officialFullNameError').style.display = 'block';
            isValid = false;
        }

        const email = document.getElementById('officialEmail').value.trim();
        const officialEmailRegex = /^[^\s@]+@[^\s@]+\.(gov\.in|org|edu)$/;
        if (!officialEmailRegex.test(email)) {
            document.getElementById('officialEmailError').textContent = 'Please enter a valid official email (gov.in, .org, or .edu domain)';
            document.getElementById('officialEmailError').style.display = 'block';
            isValid = false;
        }

        const designation = document.getElementById('officialDesignation').value;
        if (!designation) {
            document.getElementById('officialDesignationError').style.display = 'block';
            isValid = false;
        }

        const state = document.getElementById('officialState').value;
        if (!state) {
            document.getElementById('officialStateError').style.display = 'block';
            isValid = false;
        }

        const district = document.getElementById('officialDistrict').value;
        if (!district) {
            document.getElementById('officialDistrictError').style.display = 'block';
            isValid = false;
        }

        const department = document.getElementById('officialDepartment').value.trim();
        if (department.length < 3) {
            document.getElementById('officialDepartmentError').style.display = 'block';
            isValid = false;
        }

        const employeeId = document.getElementById('officialEmployeeId').value.trim();
        if (employeeId.length < 3) {
            document.getElementById('officialEmployeeIdError').style.display = 'block';
            isValid = false;
        }

        const mobile = document.getElementById('officialMobile').value.trim();
        const mobileRegex = /^[6-9]\d{9}$/;
        if (!mobileRegex.test(mobile)) {
            document.getElementById('officialMobileError').style.display = 'block';
            isValid = false;
        }

        const password = document.getElementById('officialPassword').value;
        const strongPasswordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        if (!strongPasswordRegex.test(password)) {
            document.getElementById('officialPasswordError').style.display = 'block';
            isValid = false;
        }

        const confirmPassword = document.getElementById('officialConfirmPassword').value;
        if (password !== confirmPassword) {
            document.getElementById('officialConfirmPasswordError').style.display = 'block';
            isValid = false;
        }
    }

    // Terms checkbox validation
    if (!document.getElementById('terms').checked) {
        alert('Please accept the Terms of Service and Privacy Policy to continue.');
        isValid = false;
    }

    return isValid;
}

function showModal(title) {
    alert(title + ' would be displayed in a modal window.');
}

function goToLogin() {
    // This would redirect to the login page
    window.location.href = 'login.html';
}

// Event listeners


document.getElementById('publicPassword').addEventListener('input', function (e) {
    checkPasswordStrength(e.target.value, 'publicPasswordStrength');
});

document.getElementById('officialPassword').addEventListener('input', function (e) {
    checkPasswordStrength(e.target.value, 'officialPasswordStrength');
});

// Real-time confirm password validation
document.getElementById('publicConfirmPassword').addEventListener('input', function () {
    const pwd = document.getElementById('publicPassword').value;
    const confirm = this.value;
    const err = document.getElementById('publicConfirmPasswordError');
    err.style.display = (pwd && confirm && pwd !== confirm) ? 'block' : 'none';
});

document.getElementById('officialConfirmPassword').addEventListener('input', function () {
    const pwd = document.getElementById('officialPassword').value;
    const confirm = this.value;
    const err = document.getElementById('officialConfirmPasswordError');
    err.style.display = (pwd && confirm && pwd !== confirm) ? 'block' : 'none';
});

document.getElementById('signupForm').addEventListener('submit', function (e) {
    // Allow natural form submit if valid
    if (!validateForm()) {
        e.preventDefault();
        return false;
    }

    // Make sure disabled attributes reflect current selection so inactive inputs don't block/submit
    const type = currentUserType;
    const ut = document.getElementById('userType');
    if (ut) ut.value = type;
    const publicInputs = document.querySelectorAll('#publicForm input, #publicForm select, #publicForm textarea');
    const officialInputs = document.querySelectorAll('#officialForm input, #officialForm select, #officialForm textarea');
    if (type === 'public') {
        publicInputs.forEach(el => el.disabled = false);
        officialInputs.forEach(el => el.disabled = true);
    } else {
        publicInputs.forEach(el => el.disabled = true);
        officialInputs.forEach(el => el.disabled = false);
    }
});

// Animate water drops
function animateDrops() {
    const drops = document.querySelectorAll('.water-drop');
    drops.forEach((drop, index) => {
        drop.style.animationDelay = `${index * 0.5}s`;
    });
}

animateDrops();