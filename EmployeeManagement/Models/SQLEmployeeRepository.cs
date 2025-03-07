
namespace EmployeeManagement.Models
{
    public class SQLEmployeeRepository : IEmployeeRepository
    {
        private readonly AppDbContext context;

        public SQLEmployeeRepository(AppDbContext context)
        {
            this.context = context;
        }

        public Employee Add(Employee employee)
        {
             context.Employees.Add(employee);
            context.SaveChanges();
            return employee;
        }

        public Employee Delete(int id)
        {
            var employee = context.Employees.FirstOrDefault(x => x.Id == id);
            if (employee != null)
            {
                context.Employees.Remove(employee);
            }
            context.SaveChanges();
            return employee;
        }

        public IEnumerable<Employee> GetAllEmployees()
        { 
            return context.Employees;
        }

        public Employee GetEmployee(int Id)
        {
            var employee = context.Employees.FirstOrDefault(e => e.Id == Id);

            context.SaveChanges();
            return employee;
        }

        public Employee Update(Employee employeeChanges)
        {
            var employee = context.Employees.Attach(employeeChanges);
            employee.State = Microsoft.EntityFrameworkCore.EntityState.Modified;
            context.SaveChanges();
            return employeeChanges;
        }
    }
}
