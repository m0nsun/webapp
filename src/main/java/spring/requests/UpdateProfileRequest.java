package spring.requests;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.util.Date;

@Getter
@Setter
@AllArgsConstructor
public class UpdateProfileRequest implements Serializable {
    private String first_name;
    private String last_name;
    private String phone_number;
    //private String email;
    private String birth_date;
    //private String password;
}
