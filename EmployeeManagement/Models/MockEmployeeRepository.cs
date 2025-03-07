namespace EmployeeManagement.Models
{
    public class MockEmployeeRepository : IEmployeeRepository
    {
        private List<Employee> _employeesList;
         

        public MockEmployeeRepository() {
            _employeesList = new List<Employee>()
            {
            new Employee(){ Id = 1 , Name = "Mary" ,  Department =  Dept.HR ,Email = "mary@gmail.com"},
            new Employee(){ Id = 2 , Name = "John" ,  Department =  Dept.IT  ,Email = "john@gmail.com"},
            new Employee(){ Id = 3 , Name = "Sam" ,  Department =  Dept.IT  ,Email = "sam@gmail.com"},
            };
        }
        public Employee GetEmployee(int Id)
        {
            return _employeesList.FirstOrDefault(e => e.Id == Id);
        }
        public IEnumerable<Employee> GetAllEmployees() {  
            
            return _employeesList;
        }

        public Employee Add(Employee employee)
        {
            employee.Id = _employeesList.Max(e => e.Id) +1  ;
            _employeesList.Add(employee);
            return employee;
        }

        public Employee Update(Employee employeeChanges)
        {
            Employee employee = _employeesList.FirstOrDefault(e => e.Id == employeeChanges.Id);
            if (employee != null)
            {
                employee.Name = employeeChanges.Name;
                employee.Department = employeeChanges.Department;
                employee.Email = employeeChanges.Email;

            }
            return employee;
        }

        public Employee Delete(int id)
        {
            Employee employee = _employeesList.FirstOrDefault(e => e.Id == id);
            if(employee != null)
            {
                _employeesList.Remove(employee);
            }
            return employee;
        }
    }
}
